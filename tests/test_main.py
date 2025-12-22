import base64
import datetime as dt
import hashlib
import logging
import time
import unittest
import urllib.parse
from unittest.mock import patch

import requests
import requests_mock

from eveauth import Token
from eveauth.main import Client, generate_code_challenge

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

MODULE_PATH = "eveauth.main"


@requests_mock.Mocker(real_http=True)
@patch(MODULE_PATH + ".Client._validate_jwt_token")
@patch(MODULE_PATH + ".webbrowser.open")
class TestClient_Authorize(unittest.TestCase):
    def test_should_authorize(
        self,
        mock_requests: requests_mock.mock,
        mock_webbrowser_open,
        mock_validate_jwt_token,
    ):
        def f(url: str):
            result = urllib.parse.urlparse(url)
            q = urllib.parse.parse_qs(result.query)
            state = q["state"][0]
            q2 = urllib.parse.urlencode({"state": state, "code": "code"})
            r = requests.get(f"http://127.0.0.1:8080/callback?{q2}")
            self.assertTrue(r.ok)

        mock_webbrowser_open.side_effect = f
        mock_validate_jwt_token.return_value = {
            "name": "name",
            "scp": "alpha",
            "sub": "CHARACTER:XXX:123456",
        }
        c = Client("client_id")
        mock_requests.post(
            "https://login.eveonline.com/v2/oauth/token",
            json={
                "access_token": "access_token_2",
                "refresh_token": "refresh_token_2",
            },
        )
        token = c.authorize("PublicData")
        self.assertEqual(token.character_name, "name")
        self.assertEqual(token.refresh_token, "refresh_token_2")
        self.assertEqual(token.access_token, "access_token_2")

        url: str = mock_webbrowser_open.call_args[0][0]
        p = url.split("?")
        self.assertEqual("https://login.eveonline.com/v2/oauth/authorize", p[0])
        q = urllib.parse.parse_qs(p[1])
        self.assertListEqual(q["client_id"], ["client_id"])
        self.assertListEqual(q["redirect_uri"], ["http://127.0.0.1:8080/callback"])
        self.assertListEqual(q["response_type"], ["code"])
        self.assertListEqual(q["scope"], ["PublicData"])

    def test_should_show_internal_server_error_and_abort_when_error_happens(
        self,
        mock_requests: requests_mock.mock,
        mock_webbrowser_open,
        mock_validate_jwt_token,
    ):
        def f(url: str):
            result = urllib.parse.urlparse(url)
            q = urllib.parse.parse_qs(result.query)
            state = q["state"][0]
            q2 = urllib.parse.urlencode({"state": state, "code": "code"})
            r = requests.get(f"http://127.0.0.1:8080/callback?{q2}")
            self.assertEqual(r.status_code, 500)

        mock_webbrowser_open.side_effect = f
        mock_validate_jwt_token.return_value = {
            "name": "name",
            "scp": "alpha",
            "sub": "invalid",
        }
        c = Client("client_id")
        mock_requests.post(
            "https://login.eveonline.com/v2/oauth/token",
            json={
                "access_token": "access_token_2",
                "refresh_token": "refresh_token_2",
            },
        )
        with self.assertRaises(RuntimeError):
            c.authorize("PublicData")

    def test_should_respond_with_error_when_calling_authorized_prematurely(
        self,
        _: requests_mock.mock,
        mock_webbrowser_open,
        mock_validate_jwt_token,
    ):
        def f(_):
            r = requests.get("http://127.0.0.1:8080/authorized")
            self.assertEqual(r.status_code, 200)

        mock_webbrowser_open.side_effect = f
        mock_validate_jwt_token.return_value = {}
        c = Client("client_id")
        with self.assertRaises(RuntimeError):
            c.authorize("PublicData")

    def test_should_respond_with_not_found_when_calling_undefined_route(
        self,
        _: requests_mock.mock,
        mock_webbrowser_open,
        mock_validate_jwt_token,
    ):
        def f(_):
            r = requests.get("http://127.0.0.1:8080/invalid")
            self.assertEqual(r.status_code, 404)
            r = requests.get("http://127.0.0.1:8080/authorized")
            self.assertEqual(r.status_code, 200)

        mock_webbrowser_open.side_effect = f
        mock_validate_jwt_token.return_value = {}
        c = Client("client_id")
        with self.assertRaises(RuntimeError):
            c.authorize("PublicData")


@requests_mock.Mocker()
@patch(MODULE_PATH + ".Client._validate_jwt_token")
class TestClient_RefreshToken(unittest.TestCase):
    def test_should_fetch_token(
        self,
        mock_requests: requests_mock.mock,
        mock_validate_jwt_token,
    ):
        mock_validate_jwt_token.return_value = {
            "name": "name",
            "scp": "alpha",
            "sub": "CHARACTER:XXX:123456",
        }
        c = Client("dummy")
        mock_requests.post(
            "https://login.eveonline.com/v2/oauth/token",
            json={
                "access_token": "access_token_2",
                "refresh_token": "refresh_token_2",
            },
        )
        token = Token(
            access_token="access_token",
            character_id=123,
            character_name="Bobby",
            expires_at=dt.datetime.now() + dt.timedelta(minutes=20),
            refresh_token="refresh_token",
            scopes=[],
        )
        c.refresh_token(token)
        self.assertEqual(token.character_name, "name")
        self.assertEqual(token.refresh_token, "refresh_token_2")
        self.assertEqual(token.access_token, "access_token_2")


@requests_mock.Mocker()
class TestClient_FetchJwksMetadata(unittest.TestCase):
    def test_should_fetch_data(self, mock: requests_mock.mock):
        c = Client("dummy")
        mock.get(
            "https://login.eveonline.com/.well-known/oauth-authorization-server",
            json={"jwks_uri": "https://login.eveonline.com/oauth/jwks"},
        )
        mock.get(
            "https://login.eveonline.com/oauth/jwks",
            json={"keys": "many"},
        )

        result = c._fetch_jwks_metadata()
        self.assertEqual(result, {"keys": "many"})
        self.assertEqual(mock.call_count, 2)

    def test_should_return_cache_when_not_expired(self, mock: requests_mock.mock):
        c = Client("dummy")
        my_data = {"keys": "many"}
        c._jwks_metadata = my_data
        c._jwks_metadata_ttl = time.time() + 100

        result = c._fetch_jwks_metadata()
        self.assertEqual(result, my_data)
        self.assertEqual(mock.call_count, 0)


class TestGenerateCodeChallenge(unittest.TestCase):
    def test_output_types(self):
        """Verify the function returns the correct types (bytes, str)."""
        verifier, challenge = generate_code_challenge()
        self.assertIsInstance(verifier, bytes)
        self.assertIsInstance(challenge, str)

    def test_challenge_derivation(self):
        """Verify that the challenge is a valid SHA256 hash of the verifier."""
        verifier, challenge = generate_code_challenge()

        # Manually recreate the challenge from the returned verifier
        expected_hash = hashlib.sha256(verifier).digest()
        # Use altchars or rstrip to match the function's logic
        expected_challenge = (
            base64.urlsafe_b64encode(expected_hash).decode().rstrip("=")
        )

        self.assertEqual(challenge, expected_challenge)

    def test_uniqueness(self):
        """Verify that successive calls produce different results."""
        res1 = generate_code_challenge()
        res2 = generate_code_challenge()
        self.assertNotEqual(res1[0], res2[0])
        self.assertNotEqual(res1[1], res2[1])

    def test_url_safety(self):
        """Verify the challenge contains no illegal URL characters or padding."""
        _, challenge = generate_code_challenge()
        # Challenge should not contain '=', '+', or '/'
        self.assertNotIn("=", challenge)
        self.assertNotIn("+", challenge)
        self.assertNotIn("/", challenge)


class TestToken(unittest.TestCase):
    def test_basic(self):
        token = Token(
            access_token="access_token",
            character_id=123,
            character_name="Bobby",
            expires_at=dt.datetime.now() + dt.timedelta(minutes=20),
            refresh_token="refresh_token",
            scopes=[],
        )
        self.assertTrue(token.is_valid())
        token.expires_at = dt.datetime.now() - dt.timedelta(minutes=20)
        self.assertFalse(token.is_valid())
