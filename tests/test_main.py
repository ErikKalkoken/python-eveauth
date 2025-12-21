import datetime as dt
from unittest import TestCase

from eveauth import Token


class TestToken(TestCase):
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
