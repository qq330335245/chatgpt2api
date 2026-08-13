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
            token, oai_sc, _so_token, _set_cookies = sentinel.build_sentinel_token_via_node(
                "device-1",
                "oauth_create_account",
                page_url="https://auth.openai.com/about-you",
            )
        payload = json.loads(token)
        self.assertEqual(payload.get("t"), "turnstile-value")
        self.assertEqual(oai_sc, "0challenge")

    def test_node_probe_passes_proxy(self):
        fake_token = json.dumps(
            {
                "p": "pow",
                "t": "turnstile-value",
                "c": "challenge",
                "id": "device-1",
                "flow": "email_otp_validate",
            },
            separators=(",", ":"),
        )

        class Completed:
            returncode = 0
            stdout = fake_token
            stderr = ""

        with patch.object(sentinel.subprocess, "run", return_value=Completed()) as run_mock:
            sentinel.build_sentinel_token_via_node(
                "device-1",
                "email_otp_validate",
                proxy="socks5://192.168.15.144:7891",
            )
        command = run_mock.call_args.args[0]
        self.assertIn("--proxy", command)
        self.assertEqual(command[command.index("--proxy") + 1], "socks5://192.168.15.144:7891")

    def test_bundle_uses_session_proxy(self):
        fake_token = json.dumps(
            {
                "p": "pow",
                "t": "turnstile-value",
                "c": "challenge",
                "id": "device-1",
                "flow": "email_otp_validate",
            },
            separators=(",", ":"),
        )

        class Completed:
            returncode = 0
            stdout = json.dumps(
                {
                    "token": fake_token,
                    "session_observer_token": "so-token",
                    "sentinel_req_set_cookies": [],
                }
            )
            stderr = ""

        class FakeSession:
            proxies = {"all": "socks5h://192.168.15.144:7891"}

        with patch.object(sentinel.subprocess, "run", return_value=Completed()) as run_mock:
            bundle = sentinel.build_sentinel_token_bundle(
                FakeSession(),
                "device-1",
                "email_otp_validate",
                prefer_node=True,
                with_so=True,
            )
        command = run_mock.call_args.args[0]
        self.assertEqual(bundle.get("so_token"), "so-token")
        self.assertIn("--proxy", command)
        self.assertEqual(command[command.index("--proxy") + 1], "socks5h://192.168.15.144:7891")

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
        token, oai_sc, _so_token, _set_cookies = sentinel.build_sentinel_token_via_node(
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
