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
import json
import logging
import queue
import random
import secrets
import string
import threading
import urllib.parse
import webbrowser
from dataclasses import dataclass
from functools import partial
from http import server
from typing import List, Tuple

import requests

_ACCEPTED_ISSUERS = ("login.eveonline.com", "https://login.eveonline.com")
_AUTHORIZE_URL = "https://login.eveonline.com/v2/oauth/authorize"
_RESOURCE_HOST = "login.eveonline.com"
_TOKEN_URL = "https://login.eveonline.com/v2/oauth/token"


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
        return self.expires_at > dt.datetime.now()

    @classmethod
    def _from_payload(cls, token_payload: dict) -> "Token":
        access_token = token_payload.get("access_token", "")
        if not access_token:
            raise ValueError("can not find access token in token payload")
        refresh_token = token_payload.get("refresh_token", "")
        if not refresh_token:
            raise ValueError("can not find refresh token in token payload")
        parsed = _parse_jwt(access_token)
        sub = parsed.get("sub", "")
        sub_parts = str.split(sub, ":")
        if len(sub_parts) != 3:
            raise ValueError(f"Invalid sub section: {parsed['sub']}")
        scopes = parsed["scp"]
        token = cls(
            access_token=access_token,
            refresh_token=refresh_token,
            character_id=int(sub_parts[2]),
            character_name=parsed.get("name", ""),
            expires_at=dt.datetime.fromtimestamp(parsed.get("exp", 0)),
            scopes=[scopes] if isinstance(scopes, str) else list(scopes),
        )
        return token


def _parse_jwt(access_token: str) -> dict:
    """Return the parsed content of an SSO access token."""
    # Split the token into its three parts
    parts = access_token.split(".")
    if len(parts) != 3:
        raise ValueError("Token does not have 3 parts")

    # We only need the payload (the second part)
    payload_b64 = parts[1]

    # Add padding back if necessary
    # Base64 strings must be multiples of 4
    missing_padding = len(payload_b64) % 4
    if missing_padding:
        payload_b64 += "=" * (4 - missing_padding)

    # Decode the Base64URL string
    decoded_bytes = base64.urlsafe_b64decode(payload_b64)

    payload_data = json.loads(decoded_bytes)
    if payload_data["iss"] not in _ACCEPTED_ISSUERS:
        raise ValueError(f"Invalid issuer: {payload_data["iss"]}")

    return payload_data


class _RequestHandler(server.BaseHTTPRequestHandler):
    """Handle all HTTP requests for the SSO Server."""

    token_payload = dict()

    def __init__(self, client: "Client", state: str, *args, **kwargs) -> None:
        self._client = client
        self._state = state
        super().__init__(*args, **kwargs)

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)

        if parsed_url.path == "/callback":
            query_dict = urllib.parse.parse_qs(parsed_url.query)
            data = {k: v[0] if len(v) == 1 else v for k, v in query_dict.items()}

            if data["state"] != self._state:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Invalid state")
                return

            code_verifier, _ = _generate_code_challenge()
            x = data.get("code", "")
            code = x[0] if isinstance(x, list) else x
            _RequestHandler.token_payload = self._client._fetch_token(
                code, code_verifier
            )

            self.send_response(302)
            self.send_header("Location", "/authorized")
            self.end_headers()

        elif parsed_url.path == "/authorized":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            token = Token._from_payload(_RequestHandler.token_payload)
            message = f"<p>Your app has been authorized for {token.character_name}</p>"
            self.wfile.write(message.encode("utf-8"))
            self._client._result.put(token)

        else:
            # Handle 404 for any other paths
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")


def _generate_code_challenge() -> Tuple[bytes, str]:
    """Generate a code challenge for PKCE."""
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32))
    sha256 = hashlib.sha256()
    sha256.update(code_verifier)
    code_challenge = base64.urlsafe_b64encode(sha256.digest()).decode().rstrip("=")
    return (code_verifier, code_challenge)


class Client:
    """Client is a client for authorizing desktop applications
    with the EVE Online SSO service.
    It implements OAuth 2.0 with the PKCE protocol.

    A Client instance is re-usable.
    """

    def __init__(self, client_id: str, port: int, host: str = "127.0.0.1"):
        self._client_id = str(client_id)
        self._port = int(port)
        self._host = str(host)
        self._result = queue.Queue()
        self._server_running = False

    def authorize(self, scopes: List[str]) -> Token:
        """Authorize with the SSO Service and return a token."""
        scopes = [str(x) for x in scopes]
        if self._server_running:
            raise RuntimeError("server already running")

        url, state = self._make_sso_url(
            scopes, f"http://{self._host}:{self._port}/callback"
        )
        # Start server
        # allow_reuse_address helps avoid 'Address already in use' errors on restart
        server.HTTPServer.allow_reuse_address = True
        handler = partial(_RequestHandler, self, state)
        httpd = server.HTTPServer((self._host, self._port), handler)
        thread = threading.Thread(target=httpd.serve_forever)
        thread.daemon = True  # Ensures thread dies when main script exits
        thread.start()
        logger.info(f"Server started at {httpd.server_address}")
        self._server_running = True

        webbrowser.open(url)
        token: Token = self._result.get()

        # Stops the server and cleans up the thread
        httpd.shutdown()  # Stops serve_forever loop
        httpd.server_close()  # Closes the socket
        thread.join()
        self._server_running = False
        logger.info("Server stopped.")

        return token

    def _make_sso_url(self, scopes: List[str], redirect_uri: str) -> Tuple[str, str]:
        """Generate the URL to start the SSO process and a new state and return them."""
        state = "".join(random.choices(string.ascii_letters + string.digits, k=16))
        query_params = {
            "response_type": "code",
            "client_id": self._client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes),
            "state": state,
        }
        query_string = urllib.parse.urlencode(query_params)
        return (f"{_AUTHORIZE_URL}?{query_string}", state)

    def _fetch_token(self, authorization_code: str, code_verifier: bytes) -> dict:
        """Exchange authorization code and code verifier for an access token
        and refresh token and return them.
        """
        data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "client_id": self._client_id,
            "code_verifier": code_verifier,
        }
        response = requests.post(_TOKEN_URL, data=data)
        response.raise_for_status()
        return response.json()

    def refresh_token(self, token: Token) -> None:
        """Refresh a token."""
        token_payload = self._fetch_refreshed_token(token.refresh_token)
        token_2 = Token._from_payload(token_payload)
        token.access_token = token_2.access_token
        token.refresh_token = token_2.refresh_token
        token.character_name = token_2.character_name
        token.expires_at = token_2.expires_at

    def _fetch_refreshed_token(self, refresh_token: str) -> dict:
        """Refresh a token with the SSO service and return it."""
        data = {
            "client_id": self._client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        headers = {
            "Host": _RESOURCE_HOST,
        }
        response = requests.post(_TOKEN_URL, data=data, headers=headers)
        response.raise_for_status()
        return response.json()
