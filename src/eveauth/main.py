"""A module for authorizing a Python script with the EVE online SSO.

This script is designed for desktops and has no external dependencies.

Usage:

    # Authorize the app
    c = Client(client_id="YOUR-CLIENT-ID", port=8080)
    token = c.authorize(["publicData"])

    # Refresh the token
    c.refresh_token(token)
"""

import base64
import datetime as dt
import hashlib
import logging
import queue
import random
import secrets
import string
import threading
import time
import urllib.parse
import webbrowser
from contextlib import contextmanager
from dataclasses import dataclass
from functools import partial
from http import HTTPStatus, server
from typing import Any, Dict, List, Optional, Tuple

import requests
from jose import jwt

ACCEPTED_ISSUERS = ("login.eveonline.com", "https://login.eveonline.com")
AUTHORIZE_URL = "https://login.eveonline.com/v2/oauth/authorize"
EXPECTED_AUDIENCE = "EVE Online"
METADATA_CACHE_TIME = 300  # 5 minutes
METADATA_URL = "https://login.eveonline.com/.well-known/oauth-authorization-server"
RESOURCE_HOST = "login.eveonline.com"
TOKEN_URL = "https://login.eveonline.com/v2/oauth/token"
REQUESTS_TIMEOUT = 10

logger = logging.getLogger(__name__)


@dataclass
class Token:
    """Token represents an OAuth2 token for a character in Eve Online."""

    access_token: str
    character_id: int
    character_name: str
    expires_at: dt.datetime
    refresh_token: str
    scopes: List[str]

    def is_valid(self) -> bool:
        """Report whether the token has not yet expired."""
        return self.expires_at > dt.datetime.now()

    @classmethod
    def _from_payload(cls, token_payload: dict, client: "Client") -> "Token":
        access_token = token_payload.get("access_token", "")
        if not access_token:
            raise ValueError("can not find access token in token payload")
        refresh_token = token_payload.get("refresh_token", "")
        if not refresh_token:
            raise ValueError("can not find refresh token in token payload")
        claims = client._validate_jwt_token(access_token)
        sub = claims.get("sub", "")
        sub_parts = str.split(sub, ":")
        if len(sub_parts) != 3:
            raise ValueError(f"Invalid sub section: {claims['sub']}")

        scopes = claims["scp"]
        token = cls(
            access_token=access_token,
            refresh_token=refresh_token,
            character_id=int(sub_parts[2]),
            character_name=claims.get("name", ""),
            expires_at=dt.datetime.fromtimestamp(claims.get("exp", 0)),
            scopes=[scopes] if isinstance(scopes, str) else list(scopes),
        )
        return token


class MyRequestHandler(server.BaseHTTPRequestHandler):
    """Handle all HTTP requests for the SSO Server."""

    def __init__(self, state: str, *args, **kwargs) -> None:
        self.state = state
        super().__init__(*args, **kwargs)

    def do_GET(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)

        if parsed_url.path == "/callback":
            with self.handle_error():
                query_dict = urllib.parse.parse_qs(parsed_url.query)
                data = {k: v[0] if len(v) == 1 else v for k, v in query_dict.items()}

                if data["state"] != self.state:
                    raise RuntimeError("Invalid state")

                code_verifier, _ = generate_code_challenge()
                x = data.get("code", "")
                code = x[0] if isinstance(x, list) else x

                client: Client = self.server.client  # type: ignore
                token_payload = client._fetch_token(code, code_verifier)
                token = Token._from_payload(token_payload, client)
                self.server.token = token  # type: ignore
                self.send_response(HTTPStatus.FOUND)
                self.send_header("Location", "/authorized")
                self.end_headers()

        elif parsed_url.path == "/authorized":
            with self.handle_error():
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                token: Token = self.server.token  # type: ignore
                if not token:
                    raise RuntimeError("token not found")
                message = (
                    f"<p>Your app has been authorized for {token.character_name}</p>"
                )
                self.wfile.write(message.encode("utf-8"))
                client: Client = self.server.client  # type: ignore
                client._result.put(token)

        else:
            # Show 404 for any other paths
            self.send_response(HTTPStatus.NOT_FOUND)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def log_message(self, format: str, *args: Any) -> None:
        try:
            status_code = int(args[1])
        except (IndexError, ValueError, TypeError):
            status_code = 0

        if status_code >= 400:
            logger.warning(format, *args)
            return

        logger.info(format, *args)

    @contextmanager
    def handle_error(self):
        """Show an internal server error when an exception occurred."""
        try:
            yield self  # This is what 'as' receives in the with-block
        except Exception as ex:
            logger.error("Request aborted due to exception", exc_info=True)
            self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            error_message = f"Internal Server Error: {str(ex)}"
            self.wfile.write(error_message.encode())
            raise


def generate_code_challenge() -> Tuple[bytes, str]:
    """Generate a code challenge for PKCE."""
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32))
    sha256 = hashlib.sha256()
    sha256.update(code_verifier)
    code_challenge = base64.urlsafe_b64encode(sha256.digest()).decode().rstrip("=")
    return (code_verifier, code_challenge)


class MyHTTPServer(server.HTTPServer):
    """A custom HTTP server that can handle errors."""

    def __init__(self, client: "Client", *args, **kwargs) -> None:
        self.client = client
        self.token: Optional[Token] = None
        super().__init__(*args, **kwargs)

    def handle_error(self, *_args, **_kwargs) -> None:
        # Abort all consumers waiting for the result queue when a exception occurred
        self.client._result.put(None)


class Client:
    """Client is a client for authorizing desktop applications
    with the EVE Online SSO service.
    It implements the OAuth 2.0 protocol with the PKCE authorization code flow.

    A Client instance is re-usable.
    A Client will log to the standard logger.

    The default callback is: http://127.0.0.1:8080/callback
    """

    def __init__(
        self, client_id: str, port: int = 8080, host: str = "127.0.0.1"
    ) -> None:
        self._client_id = str(client_id)
        self._port = int(port)
        self._host = str(host)
        self._result = queue.Queue(1)
        self._server_running = False
        self._jwks_metadata: Optional[dict] = None
        self._jwks_metadata_ttl = 0

    def authorize(self, *scopes: str) -> Token:
        """Authorize with the SSO Service and return a token.

        Raises a RuntimeError when authorization fails.

        Usage:

            c = Client(client_id="YOUR-CLIENT-ID", port=8080)
            token = c.authorize(["publicData"])
        """
        if self._server_running:
            raise RuntimeError("server already running")

        url, state = self._make_sso_url(
            [str(x) for x in scopes], f"http://{self._host}:{self._port}/callback"
        )
        # Start server
        # allow_reuse_address helps avoid 'Address already in use' errors on restart
        MyHTTPServer.allow_reuse_address = True
        httpd = MyHTTPServer(
            client=self,
            server_address=(self._host, self._port),
            RequestHandlerClass=partial(MyRequestHandler, state),
        )
        thread = threading.Thread(target=httpd.serve_forever)
        thread.daemon = True  # Ensures thread dies when main script exits
        thread.start()
        logger.info("Server started at %s", httpd.server_address)
        self._server_running = True

        # open the SSO start page in the local browser
        webbrowser.open(url)

        # wait for the SSO process to finish
        token: Optional[Token] = self._result.get()

        # Stops the server and clean up the thread
        httpd.shutdown()  # Stops serve_forever loop
        httpd.server_close()  # Closes the socket
        thread.join()
        self._server_running = False
        logger.info("Server stopped.")

        if not token:
            raise RuntimeError("Failed to authorize") from None

        return token

    def _make_sso_url(self, scopes: List[str], redirect_uri: str) -> Tuple[str, str]:
        """Generate the URL to open the SSO start page
        and a new state and return them.
        """
        state = "".join(random.choices(string.ascii_letters + string.digits, k=16))
        query_params = {
            "response_type": "code",
            "client_id": self._client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes),
            "state": state,
        }
        query_string = urllib.parse.urlencode(query_params)
        return (f"{AUTHORIZE_URL}?{query_string}", state)

    def _fetch_token(
        self, authorization_code: str, code_verifier: bytes
    ) -> Dict[str, Any]:
        """Exchange authorization code and code verifier for an access token
        and refresh token and return them.
        """
        data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "client_id": self._client_id,
            "code_verifier": code_verifier,
        }
        response = requests.post(TOKEN_URL, data=data, timeout=REQUESTS_TIMEOUT)
        response.raise_for_status()
        return response.json()

    def refresh_token(self, token: Token) -> None:
        """Refresh a token.

        Usage:

            c = Client(client_id="YOUR-CLIENT-ID", port=8080)
            c.refresh(token)
        """
        token_payload = self._fetch_refreshed_token(token.refresh_token)
        token_2 = Token._from_payload(token_payload, self)
        token.access_token = token_2.access_token
        token.refresh_token = token_2.refresh_token
        token.character_name = token_2.character_name
        token.expires_at = token_2.expires_at

    def _fetch_refreshed_token(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh a token with the SSO service and return it."""
        data = {
            "client_id": self._client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        headers = {
            "Host": RESOURCE_HOST,
        }
        response = requests.post(
            TOKEN_URL, data=data, headers=headers, timeout=REQUESTS_TIMEOUT
        )
        response.raise_for_status()
        return response.json()

    def _validate_jwt_token(self, token: str | bytes) -> Dict[str, Any]:
        """
        Validates a JWT Token.

        :param str token: The JWT token to validate
        :returns: The content of the validated JWT access token
        :raises ExpiredSignatureError: If the token has expired
        :raises JWTError: If the token is invalid
        """
        metadata = self._fetch_jwks_metadata()
        keys = metadata["keys"]
        header = jwt.get_unverified_header(token)
        key = [
            item
            for item in keys
            if item["kid"] == header["kid"] and item["alg"] == header["alg"]
        ].pop()
        return jwt.decode(
            token,
            key=key,
            algorithms=header["alg"],
            issuer=ACCEPTED_ISSUERS,
            audience=EXPECTED_AUDIENCE,
        )

    def _fetch_jwks_metadata(self) -> Dict[str, Any]:
        """
        Fetches the JWKS metadata from the SSO server.

        :returns: The JWKS metadata
        """
        if self._jwks_metadata and self._jwks_metadata_ttl > time.time():
            return self._jwks_metadata

        resp = requests.get(METADATA_URL, timeout=REQUESTS_TIMEOUT)
        resp.raise_for_status()
        metadata = resp.json()

        jwks_uri = metadata["jwks_uri"]
        resp = requests.get(jwks_uri, timeout=REQUESTS_TIMEOUT)
        resp.raise_for_status()
        jwks_metadata = resp.json()

        self._jwks_metadata = jwks_metadata
        self._jwks_metadata_ttl = time.time() + METADATA_CACHE_TIME
        return jwks_metadata
