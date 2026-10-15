from __future__ import annotations

import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("CHATGPT2API_AUTH_KEY", "test-auth")

from services.account_service import AccountService
from services.openai_backend_api import OpenAIBackendAPI
from services.storage.json_storage import JSONStorageBackend


def token(claims: dict) -> str:
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"a.{payload}.c"


class ImageAccountEligibilityTests(unittest.TestCase):
    def test_platform_api_token_does_not_enter_image_pool(self) -> None:
        platform = token({"client_id": "app_2SKx67EdpoN0G6j64rFvigXD", "aud": ["https://api.openai.com/v1"]})
        with tempfile.TemporaryDirectory() as tmp:
            service = AccountService(JSONStorageBackend(Path(tmp) / "accounts.json"))
            service.add_account_items([{
                "email": "platform@example.test", "access_token": platform,
                "source_type": "platform_oauth", "status": "正常", "quota": 5,
            }])
            self.assertEqual(service.get_account(platform)["status"], "正常")
            self.assertFalse(service._list_ready_candidate_tokens())
            self.assertFalse(AccountService._is_image_account_available({
                "access_token": platform, "source_type": "web", "status": "正常", "quota": 5,
            }))
            with self.assertRaisesRegex(RuntimeError, "Platform OAuth API token"):
                service.get_available_access_token()

    def test_web_session_and_platform_with_web_claim_remain_eligible(self) -> None:
        web = token({"client_id": "app_web", "https://api.openai.com/auth": {"chatgpt_account_id": "account-1"}})
        record = {"access_token": web, "source_type": "chatgpt_session", "status": "正常", "quota": 2}
        self.assertTrue(AccountService._is_image_account_available(record))
        self.assertTrue(AccountService._is_image_account_available({**record, "source_type": "platform_oauth"}))


class ImageSentinelFinalizeTests(unittest.TestCase):
    @staticmethod
    def backend() -> OpenAIBackendAPI:
        backend = object.__new__(OpenAIBackendAPI)
        backend.base_url = "https://chatgpt.com"
        backend.access_token = "dummy"
        backend.user_agent = "test"
        backend.pow_script_sources = []
        backend.pow_data_build = ""
        backend._headers = lambda path, extra=None: extra or {}
        return backend

    def test_finalize_uses_har_keys(self) -> None:
        sent: list[dict] = []

        class FakeResponse:
            status_code = 200
            def __init__(self, value):
                self.value = value
            def json(self):
                return self.value

        class FakeSession:
            def post(self, url, *, json, **kwargs):
                sent.append({"url": url, "body": json})
                if url.endswith("/prepare"):
                    return FakeResponse({"prepare_token": "prepared", "proofofwork": {"required": True, "seed": "s", "difficulty": "07"}, "turnstile": {"required": True, "dx": "dx"}})
                return FakeResponse({"token": "ready"})

        backend = self.backend()
        backend.session = FakeSession()
        with patch("services.openai_backend_api.build_legacy_requirements_token", return_value="p"), \
             patch("services.openai_backend_api.build_proof_token", return_value="proof"), \
             patch("services.openai_backend_api.solve_turnstile_token", return_value="turnstile"):
            result = backend._get_chat_requirements()
        self.assertEqual(result.token, "ready")
        self.assertEqual(sent[-1]["body"], {"prepare_token": "prepared", "proofofwork": "proof", "turnstile": "turnstile"})

    def test_required_turnstile_must_not_fall_through_as_empty(self) -> None:
        class FakeResponse:
            status_code = 200
            def json(self):
                return {"prepare_token": "prepared", "turnstile": {"required": True, "dx": "dx"}}
        class FakeSession:
            def __init__(self):
                self.calls = 0
            def post(self, *args, **kwargs):
                self.calls += 1
                return FakeResponse()
        backend = self.backend()
        backend.session = FakeSession()
        with patch("services.openai_backend_api.build_legacy_requirements_token", return_value="p"), \
             patch("services.openai_backend_api.solve_turnstile_token", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "turnstile 必需"):
                backend._get_chat_requirements()
        self.assertEqual(backend.session.calls, 1)


if __name__ == "__main__":
    unittest.main()
