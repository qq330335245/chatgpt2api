import json
import os
import unittest
from unittest.mock import patch

from utils import sentinel


class SentinelTokenTests(unittest.TestCase):
    def test_node_token_parser_requires_non_empty_t(self):
        fake_token = json.dumps(
            {
                "p": "pow",
                "t": "turnstile-value",
                "c": "challenge",
                "id": "device-1",
                "flow": "oauth_create_account",
            },
            separators=(",", ":"),
        )

        class Completed:
            returncode = 0
            stdout = fake_token
            stderr = ""

        with patch.object(sentinel.subprocess, "run", return_value=Completed()):
            token, oai_sc = sentinel.build_sentinel_token_via_node(
                "device-1",
                "oauth_create_account",
                page_url="https://auth.openai.com/about-you",
            )
        payload = json.loads(token)
        self.assertEqual(payload.get("t"), "turnstile-value")
        self.assertEqual(oai_sc, "0challenge")

    def test_prefer_node_false_uses_python_path(self):
        class FakeResp:
            status_code = 200
            text = '{"token":"challenge-token","proofofwork":{"required":false}}'

            def json(self):
                return {"token": "challenge-token", "proofofwork": {"required": False}}

        class FakeSession:
            def post(self, *args, **kwargs):
                return FakeResp()

        with patch.object(sentinel, "build_sentinel_token_via_node") as node_mock:
            token, oai_sc = sentinel.build_sentinel_token(
                FakeSession(),
                "device-1",
                "username_password_create",
                prefer_node=False,
            )
            node_mock.assert_not_called()
        payload = json.loads(token)
        self.assertEqual(payload.get("t"), "")
        self.assertEqual(payload.get("c"), "challenge-token")
        self.assertEqual(oai_sc, "0challenge-token")

    @unittest.skipUnless(os.environ.get("SENTINEL_LIVE_TEST") == "1", "set SENTINEL_LIVE_TEST=1 to hit live sentinel")
    def test_live_node_token_contains_non_empty_t(self):
        token, oai_sc = sentinel.build_sentinel_token_via_node(
            "test-device-id-python",
            "oauth_create_account",
            page_url="https://auth.openai.com/about-you",
        )
        payload = json.loads(token)
        self.assertEqual(payload.get("flow"), "oauth_create_account")
        self.assertTrue(str(payload.get("p") or "").strip())
        self.assertTrue(str(payload.get("t") or "").strip())
        self.assertTrue(str(payload.get("c") or "").strip())
        self.assertTrue(str(oai_sc or "").startswith("0"))


if __name__ == "__main__":
    unittest.main()
