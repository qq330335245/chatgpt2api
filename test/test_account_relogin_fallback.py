from __future__ import annotations

import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("CHATGPT2API_AUTH_KEY", "test-auth")

from services.account_service import AccountService
from services.storage.json_storage import JSONStorageBackend


def _jwt_with_exp(seconds_from_now: int) -> str:
    import base64
    import json

    def b64(data: dict) -> str:
        raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

    header = b64({"alg": "none", "typ": "JWT"})
    payload = b64({"exp": int(time.time()) + seconds_from_now, "iat": int(time.time()) - 10})
    return f"{header}.{payload}.sig"


class AccountReloginFallbackTests(unittest.TestCase):
    def _service(self, tmp_dir: str) -> AccountService:
        return AccountService(JSONStorageBackend(Path(tmp_dir) / "accounts.json"))

    def test_list_expiring_includes_email_only_accounts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            service = self._service(tmp_dir)
            token = _jwt_with_exp(60)
            service._accounts = {
                token: service._normalize_account(
                    {
                        "access_token": token,
                        "email": "user@example.com",
                        "status": "正常",
                    }
                )
            }
            self.assertEqual(service.list_expiring_access_tokens(), [token])

    def test_refresh_access_token_schedules_relogin_when_rt_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            service = self._service(tmp_dir)
            token = _jwt_with_exp(60)
            service._accounts = {
                token: service._normalize_account(
                    {
                        "access_token": token,
                        "email": "user@example.com",
                        "password": "secret",
                        "status": "正常",
                    }
                )
            }
            with patch.object(service, "_schedule_relogin_fallback", return_value=True) as schedule:
                result = service.refresh_access_token(token, event="test_missing_rt")
            self.assertEqual(result, token)
            schedule.assert_called_once()
            self.assertEqual(schedule.call_args.args[0], token)
            self.assertEqual(schedule.call_args.kwargs.get("reason") or schedule.call_args.args[2], "missing_refresh_token")

    def test_refresh_access_token_schedules_relogin_when_rt_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            service = self._service(tmp_dir)
            token = _jwt_with_exp(60)
            service._accounts = {
                token: service._normalize_account(
                    {
                        "access_token": token,
                        "refresh_token": "rt-demo",
                        "email": "user@example.com",
                        "status": "正常",
                    }
                )
            }
            with patch.object(
                service,
                "_request_access_token_refresh",
                side_effect=RuntimeError("oauth_refresh_http_401: invalid_grant"),
            ), patch.object(service, "_schedule_relogin_fallback", return_value=True) as schedule:
                result = service.refresh_access_token(token, force=True, event="test_rt_fail")
            self.assertEqual(result, token)
            schedule.assert_called_once()
            self.assertIn("invalid_grant", str(schedule.call_args.kwargs.get("reason") or schedule.call_args.args[2]))

    def test_password_relogin_falls_back_to_email_otp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            service = self._service(tmp_dir)
            old_token = _jwt_with_exp(60)
            new_token = _jwt_with_exp(3600)
            service._accounts = {
                old_token: service._normalize_account(
                    {
                        "access_token": old_token,
                        "email": "user@example.com",
                        "password": "bad-password",
                        "mail_inbox": "inbox@example.com",
                        "status": "正常",
                    }
                )
            }
            with patch.object(
                service,
                "_login_with_password",
                return_value={"ok": False, "error": "invalid_password", "detail": {}},
            ) as password_login, patch.object(
                service,
                "_login_with_email_otp",
                return_value={
                    "ok": True,
                    "access_token": new_token,
                    "refresh_token": "rt-new",
                    "id_token": "id-new",
                    "source_type": "email_otp",
                    "expires_at": int(time.time()) + 3600,
                },
            ) as otp_login:
                service._password_re_login_thread(
                    old_token,
                    "user@example.com",
                    "bad-password",
                    "unit_test",
                )
            password_login.assert_called_once()
            otp_login.assert_called_once()
            account = service.get_account(new_token) or service.get_account(old_token)
            self.assertIsNotNone(account)
            assert account is not None
            self.assertEqual(account.get("access_token"), new_token)
            self.assertEqual(account.get("refresh_token"), "rt-new")
            self.assertEqual(account.get("status"), "正常")




    def test_list_expiring_is_capped_and_ordered_by_exp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            service = self._service(tmp_dir)
            service._EXPIRING_TOKEN_BATCH_SIZE = 2
            near = _jwt_with_exp(30)
            mid = _jwt_with_exp(120)
            far = _jwt_with_exp(300)
            service._accounts = {}
            for token, email in ((far, "c@example.com"), (near, "a@example.com"), (mid, "b@example.com")):
                service._accounts[token] = service._normalize_account(
                    {"access_token": token, "email": email, "status": "正常"}
                )
            tokens = service.list_expiring_access_tokens()
            self.assertEqual(len(tokens), 2)
            self.assertEqual(tokens[0], near)


    def test_relogin_global_concurrency_and_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            service = self._service(tmp_dir)
            service._RELOGIN_MAX_CONCURRENT = 2
            service._RELOGIN_WATCHER_MAX_PER_ROUND = 3
            service.begin_watcher_relogin_round()

            started: list[str] = []
            current = {"n": 0, "max": 0}
            import threading

            lock = threading.Lock()
            done = threading.Event()

            def fake_thread(access_token, email, password, event, progress_id=None):
                with lock:
                    current["n"] += 1
                    current["max"] = max(current["max"], current["n"])
                    started.append(access_token)
                time.sleep(0.05)
                with lock:
                    current["n"] -= 1
                    if len(started) >= 3 and current["n"] == 0:
                        done.set()

            accounts = {}
            tokens = []
            for idx in range(6):
                token = _jwt_with_exp(60 + idx)
                tokens.append(token)
                accounts[token] = service._normalize_account(
                    {
                        "access_token": token,
                        "email": f"u{idx}@example.com",
                        "status": "正常",
                    }
                )
            service._accounts = accounts

            with patch.object(service, "_password_re_login_thread", side_effect=fake_thread):
                scheduled = [
                    service._schedule_relogin_fallback(
                        token,
                        "refresh_accounts:preflight",
                        reason="missing_refresh_token",
                    )
                    for token in tokens
                ]
                self.assertEqual(sum(1 for ok in scheduled if ok), 3)
                self.assertTrue(done.wait(timeout=2) or len(started) >= 3)
                self.assertEqual(len(started), 3)
                self.assertLessEqual(current["max"], 2)
                stats = service.get_relogin_queue_stats()
                self.assertEqual(stats["budget_remaining"], 0)
                self.assertEqual(stats["pending"], 0)



if __name__ == "__main__":
    unittest.main()
