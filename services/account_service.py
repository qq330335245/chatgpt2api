from __future__ import annotations

import base64
import json
import secrets
import time
import uuid
import zlib
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Condition, Lock, Thread
from typing import Any
from urllib.parse import urlencode

from services.config import config
from services.log_service import (
    LOG_TYPE_ACCOUNT,
    log_service,
)
from services.storage.base import StorageBackend
from utils.helper import anonymize_token


class AccountService:
    """账号池服务，使用 token -> account 的 dict 保存账号。"""

    _NEW_ACCOUNT_INVALID_GRACE_SECONDS = 10 * 60
    _INVALID_CONFIRM_SECONDS = 30
    _ACCESS_TOKEN_REFRESH_SKEW_SECONDS = 24 * 60 * 60
    _REFRESH_TOKEN_KEEPALIVE_SECONDS = 3 * 24 * 60 * 60
    _REFRESH_TOKEN_KEEPALIVE_ERROR_BACKOFF_SECONDS = 6 * 60 * 60
    _REFRESH_TOKEN_KEEPALIVE_BATCH_SIZE = 3
    _TOKEN_REFRESH_ERROR_BACKOFF_SECONDS = 5 * 60
    # 凭证快过期且 RT/密码都不可用时，重登兜底的最小间隔，避免频繁发 OTP
    _RELOGIN_FALLBACK_BACKOFF_SECONDS = 30 * 60
    # 全局最多同时跑几个重登，其余进队列
    _RELOGIN_MAX_CONCURRENT = 3
    # watcher / 批量刷新每轮最多新调度多少个重登
    _RELOGIN_WATCHER_MAX_PER_ROUND = 5
    # 每轮优先处理的快过期账号数（按 exp 升序 + 稳定 jitter）
    _EXPIRING_TOKEN_BATCH_SIZE = 40
    _OAUTH_TOKEN_URL = "https://auth.openai.com/oauth/token"
    _OAUTH_CLIENT_ID = "app_2SKx67EdpoN0G6j64rFvigXD"
    _OAUTH_USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/145.0.0.0 Safari/537.36"
    )
    _RELOGIN_SOFT_ERRORS = {
        "need_verification_code",
        "otp_timeout",
        "otp_mail_unavailable",
        "otp_validate_failed",
        "otp_no_auth_code",
        "otp_max_check_attempts",
        "passwordless_send_otp_failed",
        "rate_limit_exceeded",
        "invalid_state",
        "missing_email",
        "unexpected_about_you",
        "unexpected_login_step",
        "web_entry_failed",
        "web_entry_exception",
        "no_auth_code",
        "token_exchange_failed",
        "invalid_password",
        "missing_refresh_token",
    }
    _RELOGIN_TERMINAL_ERRORS = {
        "account_deactivated",
        "unsupported_country_region_territory",
        "missing_email",
    }

    # 刷新进度追踪
    _refresh_progress: dict[str, dict] = {}
    _refresh_progress_lock = Lock()
    # 重新登录进度追踪
    _relogin_progress: dict[str, dict] = {}
    _relogin_progress_lock = Lock()

    def __init__(self, storage_backend: StorageBackend):
        self.storage = storage_backend
        self._lock = Lock()
        self._token_refresh_lock = Lock()
        self._image_slot_condition = Condition(self._lock)
        self._index = 0
        self._accounts = self._load_accounts()
        self._relogin_inflight: set[str] = set()
        self._relogin_pending_tokens: set[str] = set()
        self._relogin_pending: deque[dict[str, Any]] = deque()
        self._relogin_active = 0
        self._relogin_inflight_lock = Lock()
        self._relogin_schedule_budget: int | None = None
        self._image_inflight: dict[str, int] = {}
        self._token_aliases: dict[str, str] = {}
        self._cumulative_total = self._load_cumulative_total()

    def _get_cumulative_file(self) -> Path:
        from services.config import DATA_DIR
        return DATA_DIR / ".cumulative_total"

    def _load_cumulative_total(self) -> int:
        try:
            f = self._get_cumulative_file()
            if f.exists():
                return int(f.read_text().strip())
        except Exception:
            pass
        return len(self._accounts)

    def _save_cumulative_total(self) -> None:
        try:
            self._get_cumulative_file().write_text(str(self._cumulative_total))
        except Exception:
            pass

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _decode_jwt_payload(token: str) -> dict:
        try:
            payload = str(token or "").split(".")[1]
            payload += "=" * ((4 - len(payload) % 4) % 4)
            import base64
            import json
            data = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    @staticmethod
    def _parse_time(value: object) -> datetime | None:
        raw = str(value or "").strip()
        if not raw:
            return None
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except Exception:
            try:
                parsed = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
            except Exception:
                return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _timestamp_to_iso(value: object) -> str:
        try:
            ts = int(value)
        except (TypeError, ValueError):
            return ""
        tz = timezone(timedelta(hours=8))
        return datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(tz).isoformat()

    def _load_accounts(self) -> dict[str, dict]:
        accounts = self.storage.load_accounts()
        return {
            normalized["access_token"]: normalized
            for item in accounts
            if (normalized := self._normalize_account(item)) is not None
        }

    def _save_accounts(self) -> None:
        self.storage.save_accounts(list(self._accounts.values()))

    @staticmethod
    def _is_image_account_available(account: dict) -> bool:
        if not isinstance(account, dict):
            return False
        if account.get("status") in {"禁用", "限流", "异常"}:
            return False
        return int(account.get("quota") or 0) > 0

    @classmethod
    def _account_matches_plan_type(cls, account: dict, plan_type: str | None = None) -> bool:
        if not plan_type:
            return True
        normalized_plan = cls._normalize_account_type(plan_type)
        normalized_account = cls._normalize_account_type(account.get("type"))
        if not normalized_plan or not normalized_account:
            return False
        return normalized_plan.lower() == normalized_account.lower()

    @classmethod
    def _account_matches_source_type(cls, account: dict, source_type: str | None = None) -> bool:
        if not source_type:
            return True
        return cls._normalize_source_type(account.get("source_type")) == cls._normalize_source_type(source_type)

    @classmethod
    def _account_matches_any_plan_type(cls, account: dict, plan_types: set[str] | tuple[str, ...] | None = None) -> bool:
        if not plan_types:
            return True
        normalized_account = cls._normalize_account_type(account.get("type"))
        normalized_plans = {
            normalized
            for plan_type in plan_types
            if (normalized := cls._normalize_account_type(plan_type))
        }
        return bool(normalized_account and normalized_account in normalized_plans)

    @staticmethod
    def _normalize_source_type(value: object) -> str:
        return str(value or "web").strip().lower() or "web"

    @staticmethod
    def _normalize_account_type(value: object) -> str | None:
        raw = str(value or "").strip()
        if not raw:
            return None
        key = raw.lower().replace("-", "_").replace(" ", "_")
        compact = key.replace("_", "")
        aliases = {
            "free": "free",
            "plus": "Plus",
            "pro": "Pro",
            "prolite": "ProLite",
            "team": "Team",
            "business": "Team",
            "enterprise": "Enterprise",
        }
        return aliases.get(compact) or aliases.get(key) or raw

    def _search_account_type(self, payload: object) -> str | None:
        if isinstance(payload, dict):
            for key in ("plan_type", "account_plan", "account_type", "subscription_type", "type"):
                plan = self._normalize_account_type(payload.get(key))
                if plan:
                    return plan
            for value in payload.values():
                plan = self._search_account_type(value)
                if plan:
                    return plan
        elif isinstance(payload, list):
            for value in payload:
                plan = self._search_account_type(value)
                if plan:
                    return plan
        return None

    def _normalize_account(self, item: dict) -> dict | None:
        if not isinstance(item, dict):
            return None
        access_token = item.get("access_token") or item.get("accessToken") or ""
        if not access_token:
            return None
        normalized = dict(item)
        normalized.pop("accessToken", None)
        normalized["access_token"] = access_token
        if str(normalized.get("type") or "").strip().lower() == "codex":
            normalized["export_type"] = "codex"
            normalized.pop("type", None)
        normalized["type"] = normalized.get("type") or "free"
        normalized["status"] = normalized.get("status") or "正常"
        normalized["quota"] = max(0, int(normalized.get("quota") if normalized.get("quota") is not None else 0))
        normalized["email"] = normalized.get("email") or None
        mail_inbox = str(
            normalized.get("mail_inbox")
            or normalized.get("otp_inbox")
            or normalized.get("receive_email")
            or ""
        ).strip()
        normalized["mail_inbox"] = mail_inbox or None
        mail_provider_ref = str(normalized.get("mail_provider_ref") or "").strip()
        normalized["mail_provider_ref"] = mail_provider_ref or None
        mail_provider_type = str(normalized.get("mail_provider_type") or "").strip()
        normalized["mail_provider_type"] = mail_provider_type or None
        normalized["user_id"] = normalized.get("user_id") or None
        normalized["proxy"] = str(normalized.get("proxy") or "").strip()
        source_type = normalized.get("source_type")
        if not source_type and str(normalized.get("export_type") or "").strip().lower() == "codex":
            source_type = "codex"
        normalized["source_type"] = self._normalize_source_type(source_type)
        limits_progress = normalized.get("limits_progress")
        normalized["limits_progress"] = limits_progress if isinstance(limits_progress, list) else []
        normalized["default_model_slug"] = normalized.get("default_model_slug") or None
        normalized["restore_at"] = normalized.get("restore_at") or None
        normalized["success"] = int(normalized.get("success") or 0)
        normalized["fail"] = int(normalized.get("fail") or 0)
        normalized["invalid_count"] = int(normalized.get("invalid_count") or 0)
        normalized["last_used_at"] = normalized.get("last_used_at")
        normalized["last_invalid_at"] = normalized.get("last_invalid_at") or None
        normalized["last_refresh_error"] = normalized.get("last_refresh_error") or None
        normalized["last_refresh_error_at"] = normalized.get("last_refresh_error_at") or None
        normalized["last_token_refresh_at"] = normalized.get("last_token_refresh_at") or None
        normalized["last_token_refresh_error"] = normalized.get("last_token_refresh_error") or None
        normalized["last_token_refresh_error_at"] = normalized.get("last_token_refresh_error_at") or None
        normalized["last_relogin_at"] = normalized.get("last_relogin_at") or None
        normalized["last_relogin_error"] = normalized.get("last_relogin_error") or None
        normalized["last_relogin_error_at"] = normalized.get("last_relogin_error_at") or None
        normalized["created_at"] = normalized.get("created_at") or AccountService._now()
        return normalized

    @staticmethod
    def _jwt_exp(access_token: str) -> int:
        try:
            return int(AccountService._decode_jwt_payload(access_token).get("exp") or 0)
        except (TypeError, ValueError):
            return 0

    @classmethod
    def _token_expires_in(cls, access_token: str) -> int | None:
        exp = cls._jwt_exp(access_token)
        if exp <= 0:
            return None
        return exp - int(time.time())

    @classmethod
    def _format_token_expiry(cls, access_token: str = "", expires_at: object = None) -> dict[str, Any]:
        """统一续期/刷新结果日志里的凭证过期字段。"""
        exp = 0
        try:
            exp = int(expires_at or 0)
        except (TypeError, ValueError):
            exp = 0
        if exp <= 0:
            exp = cls._jwt_exp(access_token)
        if exp <= 0:
            return {
                "expires_at": None,
                "expires_at_text": None,
                "expires_in_seconds": None,
            }
        dt = datetime.fromtimestamp(exp, tz=timezone.utc)
        remaining = exp - int(time.time())
        return {
            "expires_at": exp,
            "expires_at_text": dt.astimezone().strftime("%Y-%m-%d %H:%M:%S"),
            "expires_in_seconds": remaining,
        }

    @classmethod
    def _token_needs_refresh(cls, access_token: str, *, force: bool = False) -> bool:
        if force:
            return True
        remaining = cls._token_expires_in(access_token)
        return remaining is not None and remaining <= cls._ACCESS_TOKEN_REFRESH_SKEW_SECONDS

    @classmethod
    def _token_issued_at(cls, access_token: str) -> datetime | None:
        try:
            iat = int(cls._decode_jwt_payload(access_token).get("iat") or 0)
        except (TypeError, ValueError):
            return None
        if iat <= 0:
            return None
        return datetime.fromtimestamp(iat, tz=timezone.utc)

    @staticmethod
    def _safe_response_text(response: object, limit: int = 300) -> str:
        try:
            return str(getattr(response, "text", "") or "")[:limit]
        except Exception:
            return ""

    def _resolve_access_token_locked(self, access_token: str) -> str:
        token = str(access_token or "").strip()
        seen: set[str] = set()
        while token and token not in self._accounts and token in self._token_aliases and token not in seen:
            seen.add(token)
            token = self._token_aliases.get(token, token)
        return token

    def resolve_access_token(self, access_token: str) -> str:
        if not access_token:
            return ""
        with self._lock:
            return self._resolve_access_token_locked(access_token)

    def _get_account_for_token(self, access_token: str) -> tuple[str, dict | None]:
        with self._lock:
            resolved = self._resolve_access_token_locked(access_token)
            account = self._accounts.get(resolved)
            return resolved, dict(account) if account else None

    def _record_token_refresh_error(self, access_token: str, event: str, error: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            resolved = self._resolve_access_token_locked(access_token)
            current = self._accounts.get(resolved)
            if current is None:
                return
            next_item = dict(current)
            next_item["last_token_refresh_error"] = str(error or "refresh token failed")
            next_item["last_token_refresh_error_at"] = now
            account = self._normalize_account(next_item)
            if account is not None:
                self._accounts[resolved] = account
                self._save_accounts()
        log_service.add(
            LOG_TYPE_ACCOUNT,
            "refresh_token 刷新 access_token 失败",
            {"source": event, "token": anonymize_token(access_token), "error": str(error or "")},
        )

    def _recent_token_refresh_error(self, account: dict) -> bool:
        last_error_at = self._parse_time(account.get("last_token_refresh_error_at"))
        if last_error_at is None:
            return False
        return (datetime.now(timezone.utc) - last_error_at).total_seconds() < self._TOKEN_REFRESH_ERROR_BACKOFF_SECONDS


    def _account_has_relogin_email(self, account: dict | None) -> bool:
        if not isinstance(account, dict):
            return False
        return bool(str(account.get("email") or "").strip())

    def _recent_relogin_attempt(self, account: dict | None) -> bool:
        if not isinstance(account, dict):
            return False
        now = datetime.now(timezone.utc)
        for key in ("last_relogin_at", "last_relogin_error_at"):
            stamp = self._parse_time(account.get(key))
            if stamp is None:
                continue
            if (now - stamp).total_seconds() < self._RELOGIN_FALLBACK_BACKOFF_SECONDS:
                return True
        return False

    def _is_terminal_relogin_error(self, error: str, detail: object = None) -> bool:
        err = str(error or "").strip()
        err_l = err.lower()
        if err in self._RELOGIN_TERMINAL_ERRORS or err_l in self._RELOGIN_TERMINAL_ERRORS:
            return True
        if "account_deactivated" in err_l:
            return True
        if isinstance(detail, dict):
            nested = detail.get("error")
            if isinstance(nested, dict) and str(nested.get("code") or "").strip().lower() == "account_deactivated":
                return True
        return False

    def _is_soft_relogin_error(self, error: str) -> bool:
        err = str(error or "").strip()
        if err in self._RELOGIN_SOFT_ERRORS:
            return True
        err_l = err.lower()
        return any(err_l.startswith(prefix) for prefix in (
            "password_verify_failed_",
            "web_entry_",
            "oauth_refresh_http_",
        ))

    def _record_relogin_marker(
        self,
        access_token: str,
        *,
        started: bool = False,
        error: str | None = None,
    ) -> None:
        if not access_token:
            return
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            resolved = self._resolve_access_token_locked(access_token)
            current = self._accounts.get(resolved)
            if current is None:
                return
            next_item = dict(current)
            if started:
                next_item["last_relogin_at"] = now
            if error is not None:
                next_item["last_relogin_error"] = str(error or "relogin failed")
                next_item["last_relogin_error_at"] = now
            account = self._normalize_account(next_item)
            if account is not None:
                self._accounts[resolved] = account
                self._save_accounts()

    def _clear_relogin_marker(self, access_token: str) -> None:
        if not access_token:
            return
        with self._lock:
            resolved = self._resolve_access_token_locked(access_token)
            current = self._accounts.get(resolved)
            if current is None:
                return
            next_item = dict(current)
            next_item["last_relogin_error"] = None
            next_item["last_relogin_error_at"] = None
            account = self._normalize_account(next_item)
            if account is not None:
                self._accounts[resolved] = account
                self._save_accounts()

    @classmethod
    def _event_uses_relogin_budget(cls, event: str, progress_id: str | None = None) -> bool:
        """批量/巡检触发的重登吃每轮预算；手动重登不限。"""
        if progress_id:
            return False
        event_name = str(event or "").strip()
        if not event_name:
            return True
        if event_name.startswith("manual_relogin") or event_name.startswith("manual_"):
            return False
        return (
            event_name.startswith("refresh_accounts")
            or event_name.startswith("refresh_token_keepalive")
            or event_name.startswith("auto_relogin")
            or "account-watcher" in event_name
            or event_name.startswith("fetch_remote_info")
        )

    def begin_watcher_relogin_round(self, max_schedules: int | None = None) -> None:
        """watcher 每轮开始时重置重登调度预算。"""
        budget = self._RELOGIN_WATCHER_MAX_PER_ROUND if max_schedules is None else max(0, int(max_schedules))
        with self._relogin_inflight_lock:
            self._relogin_schedule_budget = budget

    def get_relogin_queue_stats(self) -> dict[str, int]:
        with self._relogin_inflight_lock:
            budget = self._relogin_schedule_budget
            return {
                "active": int(self._relogin_active),
                "pending": len(self._relogin_pending),
                "inflight": len(self._relogin_inflight),
                "budget_remaining": -1 if budget is None else int(budget),
                "max_concurrent": int(self._RELOGIN_MAX_CONCURRENT),
            }

    def _consume_relogin_budget_locked(self, event: str, progress_id: str | None = None) -> bool:
        if not self._event_uses_relogin_budget(event, progress_id):
            return True
        if self._relogin_schedule_budget is None:
            # 非 watcher 上下文的自动触发：给一个较小默认窗口，避免完全放飞
            self._relogin_schedule_budget = self._RELOGIN_WATCHER_MAX_PER_ROUND
        if self._relogin_schedule_budget <= 0:
            return False
        self._relogin_schedule_budget -= 1
        return True

    def _enqueue_relogin_job_locked(self, job: dict[str, Any]) -> None:
        token = str(job.get("access_token") or "").strip()
        if not token:
            return
        self._relogin_pending.append(job)
        self._relogin_pending_tokens.add(token)

    def _start_relogin_job(self, job: dict[str, Any]) -> None:
        active_token = str(job.get("access_token") or "").strip()
        email = str(job.get("email") or "").strip()
        password = str(job.get("password") or "").strip()
        event = str(job.get("event") or "relogin_fallback")
        reason = str(job.get("reason") or "")
        progress_id = job.get("progress_id")
        progress_id = str(progress_id) if progress_id else None

        self._record_relogin_marker(active_token, started=True)
        self._relogin_trace(
            "fallback_started",
            email=email,
            token=anonymize_token(active_token),
            reason=reason or event,
            has_password=bool(password),
            event=event,
            queue=self.get_relogin_queue_stats(),
        )
        log_service.add(
            LOG_TYPE_ACCOUNT,
            "凭证刷新失败，启动重登兜底",
            {
                "source": event,
                "token": anonymize_token(active_token),
                "email": email,
                "reason": reason,
                "has_password": bool(password),
            },
        )

        def _runner() -> None:
            try:
                self._password_re_login_thread(
                    active_token,
                    email,
                    password,
                    event,
                    progress_id,
                )
            finally:
                with self._relogin_inflight_lock:
                    self._relogin_inflight.discard(active_token)
                    self._relogin_active = max(0, int(self._relogin_active) - 1)
                    latest = None
                try:
                    latest = self.get_account(active_token) or {}
                except Exception:
                    latest = {}
                latest_token = str((latest or {}).get("access_token") or "").strip()
                with self._relogin_inflight_lock:
                    if latest_token:
                        self._relogin_inflight.discard(latest_token)
                self._pump_relogin_queue()

        Thread(
            target=_runner,
            name=f"relogin-fallback-{anonymize_token(active_token)}",
            daemon=True,
        ).start()

    def _pump_relogin_queue(self) -> None:
        """把排队中的重登任务填满到全局并发上限。"""
        while True:
            job: dict[str, Any] | None = None
            with self._relogin_inflight_lock:
                if self._relogin_active >= self._RELOGIN_MAX_CONCURRENT:
                    return
                while self._relogin_pending:
                    candidate = self._relogin_pending.popleft()
                    token = str(candidate.get("access_token") or "").strip()
                    self._relogin_pending_tokens.discard(token)
                    if not token:
                        continue
                    if token in self._relogin_inflight:
                        continue
                    self._relogin_inflight.add(token)
                    self._relogin_active += 1
                    job = candidate
                    break
                if job is None:
                    return
            self._start_relogin_job(job)

    def _schedule_relogin_fallback(
        self,
        access_token: str,
        event: str,
        reason: str = "",
        progress_id: str | None = None,
    ) -> bool:
        """RT 刷新失败或缺失时，排队走密码/邮件 OTP 重登兜底。

        - 全局最多同时 _RELOGIN_MAX_CONCURRENT 个重登
        - watcher/批量刷新受每轮预算限制
        - 同账号 inflight/pending/backoff 去重
        """
        resolved_token, account = self._get_account_for_token(access_token)
        if not account:
            return False
        active_token = str(account.get("access_token") or resolved_token or access_token).strip()
        email = str(account.get("email") or "").strip()
        if not email:
            return False
        if self._recent_relogin_attempt(account):
            self._relogin_trace(
                "fallback_skipped_backoff",
                email=email,
                token=anonymize_token(active_token),
                reason=reason or event,
            )
            return False

        password = str(account.get("password") or "").strip()
        job = {
            "access_token": active_token,
            "email": email,
            "password": password,
            "event": event,
            "reason": str(reason or ""),
            "progress_id": progress_id,
        }

        with self._relogin_inflight_lock:
            if active_token in self._relogin_inflight or active_token in self._relogin_pending_tokens:
                self._relogin_trace(
                    "fallback_skipped_inflight",
                    email=email,
                    token=anonymize_token(active_token),
                    reason=reason or event,
                    pending=active_token in self._relogin_pending_tokens,
                )
                return False
            if not self._consume_relogin_budget_locked(event, progress_id):
                self._relogin_trace(
                    "fallback_skipped_budget",
                    email=email,
                    token=anonymize_token(active_token),
                    reason=reason or event,
                    budget_remaining=int(self._relogin_schedule_budget or 0),
                )
                return False
            self._enqueue_relogin_job_locked(job)
            self._relogin_trace(
                "fallback_queued",
                email=email,
                token=anonymize_token(active_token),
                reason=reason or event,
                has_password=bool(password),
                event=event,
                active=int(self._relogin_active),
                pending=len(self._relogin_pending),
                budget_remaining=(-1 if self._relogin_schedule_budget is None else int(self._relogin_schedule_budget)),
            )

        self._pump_relogin_queue()
        return True

    def _recent_refresh_token_keepalive_error(self, account: dict, now: datetime) -> bool:
        last_error_at = self._parse_time(account.get("last_token_refresh_error_at"))
        if last_error_at is None:
            return False
        return (now - last_error_at).total_seconds() < self._REFRESH_TOKEN_KEEPALIVE_ERROR_BACKOFF_SECONDS

    def _refresh_token_keepalive_anchor(self, account: dict) -> datetime | None:
        return (
            self._parse_time(account.get("last_token_refresh_at"))
            or self._token_issued_at(str(account.get("access_token") or ""))
            or self._parse_time(account.get("created_at"))
        )

    def _refresh_token_keepalive_due_at(self, account: dict, now: datetime) -> datetime | None:
        if not str(account.get("refresh_token") or "").strip():
            return None
        if account.get("status") == "禁用":
            return None
        if self._recent_refresh_token_keepalive_error(account, now):
            return None
        anchor = self._refresh_token_keepalive_anchor(account)
        if anchor is None:
            return now
        due_at = anchor + timedelta(seconds=self._REFRESH_TOKEN_KEEPALIVE_SECONDS)
        return due_at if due_at <= now else None

    def _request_access_token_refresh(self, refresh_token: str, account: dict | None = None) -> dict[str, str]:
        from curl_cffi import requests
        from services.proxy_service import proxy_settings

        session = requests.Session(**proxy_settings.build_session_kwargs(account=account, impersonate="chrome110", verify=True))
        try:
            response = session.post(
                self._OAUTH_TOKEN_URL,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": self._OAUTH_USER_AGENT,
                },
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": self._OAUTH_CLIENT_ID,
                },
                timeout=60,
            )
            data = response.json() if response.text else {}
            if response.status_code != 200 or not isinstance(data, dict) or not data.get("access_token"):
                detail = ""
                if isinstance(data, dict):
                    detail = str(data.get("error_description") or data.get("error") or data.get("message") or "")
                detail = detail or self._safe_response_text(response)
                raise RuntimeError(f"oauth_refresh_http_{response.status_code}{': ' + detail if detail else ''}")
            return {
                "access_token": str(data.get("access_token") or "").strip(),
                "refresh_token": str(data.get("refresh_token") or refresh_token).strip(),
                "id_token": str(data.get("id_token") or "").strip(),
            }
        finally:
            session.close()

    def _apply_refreshed_tokens(self, old_access_token: str, token_data: dict, event: str) -> str:
        now = datetime.now(timezone.utc).isoformat()
        with self._image_slot_condition:
            old_token = self._resolve_access_token_locked(old_access_token)
            current = self._accounts.get(old_token)
            if current is None:
                return old_token
            new_token = str(token_data.get("access_token") or old_token).strip()
            if not new_token:
                return old_token

            next_item = dict(current)
            next_item["access_token"] = new_token
            if token_data.get("refresh_token"):
                next_item["refresh_token"] = str(token_data.get("refresh_token") or "").strip()
            if token_data.get("id_token"):
                next_item["id_token"] = str(token_data.get("id_token") or "").strip()
            next_item["last_token_refresh_at"] = now
            next_item["last_token_refresh_error"] = None
            next_item["last_token_refresh_error_at"] = None
            next_item["last_relogin_error"] = None
            next_item["last_relogin_error_at"] = None
            next_item["invalid_count"] = 0
            next_item["last_invalid_at"] = None
            next_item["last_refresh_error"] = None
            next_item["last_refresh_error_at"] = None

            account = self._normalize_account(next_item)
            if account is None:
                return old_token

            rotated = new_token != old_token
            if rotated:
                self._accounts.pop(old_token, None)
                self._token_aliases[old_token] = new_token
                old_inflight = int(self._image_inflight.pop(old_token, 0))
                if old_inflight:
                    self._image_inflight[new_token] = int(self._image_inflight.get(new_token, 0)) + old_inflight
            self._accounts[new_token] = account
            self._save_accounts()
            self._image_slot_condition.notify_all()

        expiry = self._format_token_expiry(new_token)
        log_service.add(
            LOG_TYPE_ACCOUNT,
            "refresh_token 已刷新 access_token",
            {
                "source": event,
                "token": anonymize_token(new_token),
                "rotated": rotated,
                "expires_at": expiry.get("expires_at"),
                "expires_at_text": expiry.get("expires_at_text"),
                "expires_in_seconds": expiry.get("expires_in_seconds"),
            },
        )
        return new_token

    def refresh_access_token(self, access_token: str, *, force: bool = False, event: str = "refresh_access_token") -> str:
        if not access_token:
            return ""
        with self._token_refresh_lock:
            resolved_token, account = self._get_account_for_token(access_token)
            if not account:
                return access_token
            active_token = str(account.get("access_token") or resolved_token or access_token)
            if not self._token_needs_refresh(active_token, force=force):
                return active_token

            refresh_token = str(account.get("refresh_token") or "").strip()
            fallback_reason = ""

            if refresh_token and (force or not self._recent_token_refresh_error(account)):
                try:
                    token_data = self._request_access_token_refresh(refresh_token, account)
                except Exception as exc:
                    fallback_reason = str(exc or "refresh_token_failed")
                    self._record_token_refresh_error(active_token, event, fallback_reason)
                else:
                    return self._apply_refreshed_tokens(active_token, token_data, event)
            elif not refresh_token:
                fallback_reason = "missing_refresh_token"
            else:
                fallback_reason = str(account.get("last_token_refresh_error") or "recent_refresh_token_error")

            # RT 不可用/失败时，若账号仍有邮箱，则走密码 -> 邮件 OTP 重登兜底
            if self._account_has_relogin_email(account):
                self._schedule_relogin_fallback(active_token, event, reason=fallback_reason)
            return active_token


    @staticmethod
    def _relogin_trace(step: str, **fields: Any) -> None:
        """Print one full re-login step to console for live diagnosis."""
        parts: list[str] = []
        for key, value in fields.items():
            if value is None:
                continue
            if isinstance(value, (dict, list, tuple, set)):
                try:
                    text_value = json.dumps(value, ensure_ascii=False, default=str)
                except Exception:
                    text_value = str(value)
            else:
                text_value = str(value)
            if len(text_value) > 900:
                text_value = text_value[:900] + "..."
            parts.append(f"{key}={text_value}")
        suffix = (" | " + " | ".join(parts)) if parts else ""
        print(f"[relogin] {step}{suffix}", flush=True)

    def _password_re_login_thread(self, access_token: str, email: str, password: str, event: str, progress_id: str | None = None) -> None:
        """账号重新登录线程入口。

        级联顺序：
        1. 有密码时先走密码登录（必要时含 OTP 二步）
        2. 密码失败且非终态错误时，再走纯邮件验证码登录兜底
        3. 无密码时直接走纯邮件验证码登录
        """
        login_method = "password" if str(password or "").strip() else "email_otp"
        try:
            self._relogin_trace(
                "thread_start",
                event=event,
                email=email,
                has_password=bool(str(password or "").strip()),
                token=anonymize_token(access_token),
                progress_id=progress_id or "",
            )
            account = self.get_account(access_token) or {}
            receive_email = str(
                account.get("mail_inbox")
                or account.get("otp_inbox")
                or account.get("receive_email")
                or ""
            ).strip()
            mail_provider_ref = str(account.get("mail_provider_ref") or "").strip()
            mail_provider_type = str(account.get("mail_provider_type") or "").strip()
            self._relogin_trace(
                "account_context",
                email=email,
                receive_email=receive_email,
                mail_provider_ref=mail_provider_ref,
                mail_provider_type=mail_provider_type,
                method=login_method,
            )

            result: dict[str, Any] = {"ok": False, "error": "no_login_method"}
            methods_tried: list[str] = []

            if str(password or "").strip():
                methods_tried.append("password")
                self._relogin_trace("login_begin", email=email, method="password")
                result = self._login_with_password(
                    email,
                    password,
                    receive_email=receive_email,
                    mail_provider_ref=mail_provider_ref,
                    mail_provider_type=mail_provider_type,
                )
                login_method = "password"
                self._relogin_trace(
                    "login_result",
                    email=email,
                    method="password",
                    ok=bool(result.get("ok")),
                    error=str(result.get("error") or ""),
                    detail=result.get("detail") if not result.get("ok") else None,
                )
                if result.get("ok"):
                    pass
                elif self._is_terminal_relogin_error(str(result.get("error") or ""), result.get("detail")):
                    pass
                else:
                    self._relogin_trace(
                        "password_fallback_to_email_otp",
                        email=email,
                        error=str(result.get("error") or ""),
                    )
                    methods_tried.append("email_otp")
                    self._relogin_trace("login_begin", email=email, method="email_otp")
                    otp_result = self._login_with_email_otp(
                        email,
                        receive_email=receive_email,
                        mail_provider_ref=mail_provider_ref,
                        mail_provider_type=mail_provider_type,
                    )
                    self._relogin_trace(
                        "login_result",
                        email=email,
                        method="email_otp",
                        ok=bool(otp_result.get("ok")),
                        error=str(otp_result.get("error") or ""),
                        detail=otp_result.get("detail") if not otp_result.get("ok") else None,
                    )
                    if otp_result.get("ok"):
                        result = otp_result
                        login_method = "email_otp_fallback"
                    else:
                        result = otp_result
                        login_method = "email_otp_fallback"
            else:
                methods_tried.append("email_otp")
                login_method = "email_otp"
                self._relogin_trace("login_begin", email=email, method="email_otp")
                result = self._login_with_email_otp(
                    email,
                    receive_email=receive_email,
                    mail_provider_ref=mail_provider_ref,
                    mail_provider_type=mail_provider_type,
                )
                self._relogin_trace(
                    "login_result",
                    email=email,
                    method="email_otp",
                    ok=bool(result.get("ok")),
                    error=str(result.get("error") or ""),
                    detail=result.get("detail") if not result.get("ok") else None,
                )

            if result.get("ok"):
                new_access_token = str(result.get("access_token") or "")
                new_refresh_token = result.get("refresh_token", "")
                new_id_token = result.get("id_token", "")
                new_expires_at = result.get("expires_at")

                token_data = {
                    "access_token": new_access_token,
                    "refresh_token": new_refresh_token,
                    "id_token": new_id_token,
                }
                new_token = self._apply_refreshed_tokens(access_token, token_data, f"{event}:relogin")
                self.update_account(new_token, {
                    "source_type": result.get("source_type", login_method),
                    "status": "正常",
                    "last_relogin_error": None,
                    "last_relogin_error_at": None,
                }, quiet=True)
                self._clear_relogin_marker(new_token)

                expiry = self._format_token_expiry(new_access_token or new_token, new_expires_at)
                self._relogin_trace(
                    "renew_success",
                    email=email,
                    method=login_method,
                    methods_tried=methods_tried,
                    old_token=anonymize_token(access_token),
                    new_token=anonymize_token(new_access_token or new_token),
                    expires_at=expiry.get("expires_at"),
                    expires_at_text=expiry.get("expires_at_text"),
                    expires_in_seconds=expiry.get("expires_in_seconds"),
                )
                log_service.add(
                    LOG_TYPE_ACCOUNT,
                    "账号续期成功",
                    {
                        "source": event,
                        "method": login_method,
                        "methods_tried": methods_tried,
                        "old_token": anonymize_token(access_token),
                        "new_token": anonymize_token(new_access_token or new_token),
                        "email": email,
                        "status": "成功",
                        "expires_at": expiry.get("expires_at"),
                        "expires_at_text": expiry.get("expires_at_text"),
                        "expires_in_seconds": expiry.get("expires_in_seconds"),
                    },
                )
                if progress_id:
                    self.update_relogin_progress(
                        progress_id,
                        access_token,
                        "成功",
                        extra={
                            "email": email,
                            "method": login_method,
                            "methods_tried": methods_tried,
                            "expires_at": expiry.get("expires_at"),
                            "expires_at_text": expiry.get("expires_at_text"),
                            "expires_in_seconds": expiry.get("expires_in_seconds"),
                        },
                    )
                return

            error_type = str(result.get("error") or "")
            soft = self._is_soft_relogin_error(error_type)
            terminal = self._is_terminal_relogin_error(error_type, result.get("detail"))
            fail_payload = {
                "source": event,
                "method": login_method,
                "methods_tried": methods_tried,
                "token": anonymize_token(access_token),
                "email": email,
                "status": "失败",
                "error": error_type,
                "detail": result.get("detail", {}),
            }
            self._relogin_trace(
                "renew_failed",
                email=email,
                method=login_method,
                methods_tried=methods_tried,
                error=error_type,
                soft=soft,
                terminal=terminal,
                detail=result.get("detail", {}),
            )
            self._record_relogin_marker(access_token, error=error_type or "relogin failed")

            if soft and not terminal:
                fail_payload["soft"] = True
                log_service.add(LOG_TYPE_ACCOUNT, "账号续期失败", fail_payload)
                if progress_id:
                    self.update_relogin_progress(
                        progress_id,
                        access_token,
                        "失败",
                        error_type,
                        extra={
                            "email": email,
                            "method": login_method,
                            "methods_tried": methods_tried,
                            "detail": result.get("detail", {}),
                        },
                    )
                return

            log_service.add(LOG_TYPE_ACCOUNT, "账号续期失败", fail_payload)
            if terminal and (
                error_type == "account_deactivated"
                or "account_deactivated" in error_type.lower()
                or (
                    error_type == "password_verify_failed_403"
                    and isinstance(result.get("detail"), dict)
                    and isinstance(result["detail"].get("error"), dict)
                    and result["detail"]["error"].get("code") == "account_deactivated"
                )
            ):
                self.update_account(access_token, {"status": "禁用", "quota": 0}, quiet=True)
                log_service.add(
                    LOG_TYPE_ACCOUNT,
                    "账号已停用-标记禁用",
                    {
                        "source": event,
                        "method": login_method,
                        "token": anonymize_token(access_token),
                        "email": email,
                        "detail": result.get("detail", {}),
                    },
                )
                if progress_id:
                    self.update_relogin_progress(progress_id, access_token, "禁用")
                return

            self.remove_invalid_token(access_token, f"{event}:relogin_failed", quiet=True)
            if progress_id:
                self.update_relogin_progress(progress_id, access_token, "异常", error_type)
        except Exception as exc:
            self._relogin_trace(
                "renew_exception",
                email=email,
                method=login_method,
                error=str(exc),
            )
            log_service.add(
                LOG_TYPE_ACCOUNT,
                "账号续期异常",
                {
                    "source": event,
                    "method": login_method,
                    "token": anonymize_token(access_token),
                    "email": email,
                    "status": "异常",
                    "error": str(exc),
                },
            )
            self._record_relogin_marker(access_token, error=str(exc))
            self.remove_invalid_token(access_token, f"{event}:relogin_exception", quiet=True)
            if progress_id:
                self.update_relogin_progress(progress_id, access_token, "异常", str(exc))


    def _load_relogin_mail_config(self) -> dict:
        """复用注册页配置的邮箱服务，默认 Cloudflare Temp Mail 等 providers。"""
        from services.config import DATA_DIR

        mail = {
            "request_timeout": 30,
            "wait_timeout": 90,
            "wait_interval": 2,
            "providers": [],
            "api_use_register_proxy": True,
        }
        register_proxy = ""
        try:
            raw = json.loads((DATA_DIR / "register.json").read_text(encoding="utf-8"))
            if isinstance(raw.get("mail"), dict):
                mail = {**mail, **raw["mail"]}
            register_proxy = str(raw.get("proxy") or "").strip()
        except Exception:
            pass

        # Prefer dedicated mail_providers.json (same source as scripts/relogin_tokens.py).
        # register.json often keeps CF disabled while mail_providers.json has production CF/2925/iCloud.
        try:
            mp_path = DATA_DIR / "mail_providers.json"
            if mp_path.is_file():
                mp_raw = json.loads(mp_path.read_text(encoding="utf-8"))
                if isinstance(mp_raw, dict):
                    mp_mail = mp_raw.get("mail") if isinstance(mp_raw.get("mail"), dict) else mp_raw
                    if isinstance(mp_mail, dict) and isinstance(mp_mail.get("providers"), list) and mp_mail.get("providers"):
                        mail = {**mail, **mp_mail}
        except Exception:
            pass

        try:
            mail["wait_timeout"] = max(float(mail.get("wait_timeout") or 30), 90.0)
        except Exception:
            mail["wait_timeout"] = 90.0
        try:
            mail["wait_interval"] = max(0.5, float(mail.get("wait_interval") or 2))
        except Exception:
            mail["wait_interval"] = 2.0

        use_register_proxy = True
        flag = mail.get("api_use_register_proxy")
        if isinstance(flag, bool):
            use_register_proxy = flag
        elif str(flag or "").strip().lower() in {"0", "false", "no", "off"}:
            use_register_proxy = False

        proxy = register_proxy if use_register_proxy else ""
        if not proxy:
            try:
                proxy = str(config.get_proxy_settings() or "").strip()
            except Exception:
                proxy = ""
        mail["proxy"] = proxy
        mail["api_use_register_proxy"] = use_register_proxy
        return mail

    @staticmethod
    def _extract_auth_code_from_payload(data: dict | None) -> str:
        from urllib.parse import parse_qs, urlparse

        if not isinstance(data, dict):
            return ""
        continue_url = str(data.get("continue_url") or "").strip()
        if not continue_url:
            return ""
        try:
            params = parse_qs(urlparse(continue_url).query)
        except Exception:
            return ""
        return str((params.get("code") or [""])[0]).strip()

    def _send_login_email_otp(self, session, device_id: str, headers: dict) -> None:
        auth_base = "https://auth.openai.com"
        otp_headers = dict(headers or {})
        otp_headers["referer"] = f"{auth_base}/email-verification"
        otp_headers["oai-device-id"] = device_id
        try:
            resp = session.get(
                f"{auth_base}/api/accounts/email-otp/send",
                headers=otp_headers,
                allow_redirects=True,
                timeout=30,
            )
            if getattr(resp, "status_code", None) in (200, 302):
                return
        except Exception:
            pass
        try:
            session.post(
                f"{auth_base}/api/accounts/email-otp/send",
                headers=otp_headers,
                json={},
                timeout=30,
            )
        except Exception:
            pass

    def _validate_login_email_otp(self, session, device_id: str, code: str, headers: dict) -> dict:
        auth_base = "https://auth.openai.com"
        otp_headers = dict(headers or {})
        otp_headers["referer"] = f"{auth_base}/email-verification"
        otp_headers["oai-device-id"] = device_id
        otp_headers["content-type"] = "application/json"
        otp_headers["accept"] = "application/json"

        def _do_validate(current_headers: dict):
            resp = session.post(
                f"{auth_base}/api/accounts/email-otp/validate",
                headers=current_headers,
                json={"code": code},
                timeout=30,
            )
            data = {}
            try:
                data = resp.json() if resp.text else {}
            except Exception:
                data = {}
            return resp, data if isinstance(data, dict) else {}

        resp, data = _do_validate(otp_headers)
        self._relogin_trace(
            "otp_validate_attempt",
            code=code,
            status=getattr(resp, "status_code", None),
            has_auth_code=bool(self._extract_auth_code_from_payload(data if isinstance(data, dict) else {})),
            continue_url=str((data or {}).get("continue_url") or "") if isinstance(data, dict) else "",
            page=(data.get("page") if isinstance(data, dict) else None),
            body_preview=data if isinstance(data, dict) else {},
        )
        if getattr(resp, "status_code", None) != 200:
            try:
                from utils.sentinel import build_sentinel_token

                sentinel_val, oai_sc_val = build_sentinel_token(session, device_id, "authorize_continue")
                otp_headers["openai-sentinel-token"] = sentinel_val
                if oai_sc_val:
                    session.cookies.set("oai-sc", oai_sc_val, domain=".openai.com")
                    session.cookies.set("oai-sc", oai_sc_val, domain=".auth.openai.com")
            except Exception:
                pass
            resp, data = _do_validate(otp_headers)

            self._relogin_trace(
                "otp_validate_retry",
                code=code,
                status=getattr(resp, "status_code", None),
                has_auth_code=bool(self._extract_auth_code_from_payload(data if isinstance(data, dict) else {})),
                continue_url=str((data or {}).get("continue_url") or "") if isinstance(data, dict) else "",
                page=(data.get("page") if isinstance(data, dict) else None),
            )

        if getattr(resp, "status_code", None) != 200:
            self._relogin_trace(
                "otp_validate_http_failed",
                code=code,
                status=getattr(resp, "status_code", None),
                detail=data or (getattr(resp, "text", None) or "")[:300],
            )
            return {
                "ok": False,
                "error": "otp_validate_failed",
                "detail": data or {
                    "status": getattr(resp, "status_code", None),
                    "text": (getattr(resp, "text", None) or "")[:300],
                },
            }

        auth_code = self._extract_auth_code_from_payload(data)
        if not auth_code:
            continue_url = str(data.get("continue_url") or "").strip()
            if continue_url:
                try:
                    follow = session.get(
                        continue_url,
                        headers={
                            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                            "user-agent": self._OAUTH_USER_AGENT,
                            "referer": f"{auth_base}/email-verification",
                        },
                        allow_redirects=True,
                        timeout=30,
                    )
                    from urllib.parse import parse_qs, urlparse

                    candidates = [str(getattr(follow, "url", "") or "")]
                    history = getattr(follow, "history", None) or []
                    candidates.extend(str(getattr(item, "url", "") or "") for item in history)
                    for url in candidates:
                        if not url:
                            continue
                        params = parse_qs(urlparse(url).query)
                        auth_code = str((params.get("code") or [""])[0]).strip()
                        if auth_code:
                            break
                except Exception:
                    pass

        page_type = ""
        if isinstance(data, dict) and isinstance(data.get("page"), dict):
            page_type = str(data.get("page", {}).get("type") or "")
        continue_url = str((data or {}).get("continue_url") or "") if isinstance(data, dict) else ""
        self._relogin_trace(
            "otp_validate_done",
            code=code,
            has_auth_code=bool(auth_code),
            auth_code_prefix=(auth_code[:8] + "...") if auth_code else "",
            continue_url=continue_url,
            page_type=page_type,
            about_you=("about-you" in continue_url or page_type == "about_you"),
        )
        return {"ok": True, "auth_code": auth_code, "detail": data}

    def _complete_email_otp_login(
        self,
        session,
        device_id: str,
        email: str,
        headers: dict,
        *,
        send_otp: bool = True,
        receive_email: str = "",
        mail_provider_ref: str = "",
        mail_provider_type: str = "",
    ) -> dict:
        """通过配置的邮箱服务收信并完成 email-otp/validate。

        receive_email: 代收箱地址（如 CF catch-all）
        mail_provider_ref/type: 账号绑定的邮箱服务，避免多服务时顺序盲试
        """
        from services.register import mail_provider

        self._relogin_trace(
            "otp_complete_begin",
            email=email,
            receive_email=receive_email,
            mail_provider_ref=mail_provider_ref,
            mail_provider_type=mail_provider_type,
            send_otp=send_otp,
        )
        try:
            mail_config = self._load_relogin_mail_config()
            providers = mail_config.get("providers") if isinstance(mail_config.get("providers"), list) else []
            if not providers:
                return {
                    "ok": False,
                    "error": "otp_mail_unavailable",
                    "detail": {"message": "register mail.providers 为空，请先配置邮箱服务"},
                }
            mailbox = mail_provider.get_existing_mailbox(
                mail_config,
                email,
                receive_email=str(receive_email or "").strip(),
                provider_ref=str(mail_provider_ref or "").strip(),
                provider_type=str(mail_provider_type or "").strip(),
            )
            self._relogin_trace(
                "otp_mailbox_ready",
                email=email,
                mailbox_email=str((mailbox or {}).get("email") or (mailbox or {}).get("address") or ""),
                inbox=str((mailbox or {}).get("inbox") or (mailbox or {}).get("receive_email") or receive_email or ""),
                provider=str((mailbox or {}).get("provider") or (mailbox or {}).get("provider_type") or mail_provider_type or ""),
                provider_ref=str((mailbox or {}).get("provider_ref") or mail_provider_ref or ""),
                wait_timeout=mail_config.get("wait_timeout"),
                wait_interval=mail_config.get("wait_interval"),
                proxy=bool(str(mail_config.get("proxy") or "").strip()),
            )
        except Exception as exc:
            return {
                "ok": False,
                "error": "otp_mail_unavailable",
                "detail": {
                    "message": str(exc),
                    "email": email,
                    "receive_email": receive_email,
                    "mail_provider_ref": mail_provider_ref,
                    "mail_provider_type": mail_provider_type,
                },
            }

        if send_otp:
            self._send_login_email_otp(session, device_id, headers)
            self._relogin_trace("otp_send_email_otp", email=email, path="email-otp/send")
        # 发码后再开窗；只略向前，避免共享代收箱旧码误用
        mailbox["_code_not_before"] = datetime.now(timezone.utc) - timedelta(seconds=15)

        tried: set[str] = set()
        deadline = time.time() + float(mail_config.get("wait_timeout") or 90)
        last_detail: dict[str, Any] = {}
        while time.time() < deadline:
            remaining = max(2.0, deadline - time.time())
            poll_config = {**mail_config, "wait_timeout": min(remaining, 15.0)}
            try:
                code = mail_provider.wait_for_code(poll_config, mailbox)
            except Exception as exc:
                return {
                    "ok": False,
                    "error": "otp_mail_unavailable",
                    "detail": {"message": str(exc), "email": email},
                }
            if not code or code in tried:
                continue
            tried.add(code)
            self._relogin_trace(
                "otp_code_received",
                email=email,
                code=code,
                tried_before=sorted(tried - {code}),
                remaining=round(max(0.0, deadline - time.time()), 1),
            )
            result = self._validate_login_email_otp(session, device_id, code, headers)
            if result.get("ok"):
                if str(result.get("auth_code") or "").strip():
                    self._relogin_trace(
                        "otp_code_accepted",
                        email=email,
                        code=code,
                        auth_code_prefix=str(result.get("auth_code") or "")[:8] + "...",
                    )
                    return result
                last_detail = result.get("detail") if isinstance(result.get("detail"), dict) else {}
                page = last_detail.get("page") if isinstance(last_detail.get("page"), dict) else {}
                is_about_you = (
                    "about-you" in str(last_detail.get("continue_url") or "")
                    or str(page.get("type") or "") == "about_you"
                )
                self._relogin_trace(
                    "otp_validate_ok_no_auth_code",
                    email=email,
                    code=code,
                    continue_url=str(last_detail.get("continue_url") or ""),
                    page_type=str(page.get("type") or ""),
                    about_you=is_about_you,
                    detail=last_detail,
                )
                # about-you means incomplete profile / re-onboarding; stop OTP loop
                if is_about_you:
                    return {
                        "ok": False,
                        "error": "unexpected_about_you",
                        "detail": last_detail or {"email": email, "code": code},
                    }
                continue
            last_detail = result.get("detail") if isinstance(result.get("detail"), dict) else {"error": result.get("error")}
            detail_text = json.dumps(last_detail, ensure_ascii=False).lower()
            # permanent account states: stop waiting for more OTPs
            err_obj = last_detail.get("error") if isinstance(last_detail.get("error"), dict) else {}
            err_code = str(err_obj.get("code") or "").strip().lower()
            if err_code in {"account_deactivated", "account_deleted", "user_banned", "account_banned"} or "account_deactivated" in detail_text or "has been deleted or deactivated" in detail_text:
                self._relogin_trace(
                    "otp_account_deactivated",
                    email=email,
                    code=code,
                    last=last_detail,
                )
                return {
                    "ok": False,
                    "error": "account_deactivated",
                    "detail": {"email": email, "code": code, "last": last_detail},
                }
            if "max_check_attempts" in detail_text or "too many tries" in detail_text:
                self._relogin_trace(
                    "otp_max_check_attempts",
                    email=email,
                    tried=sorted(tried),
                    last=last_detail,
                )
                return {
                    "ok": False,
                    "error": "otp_max_check_attempts",
                    "detail": {"email": email, "tried": sorted(tried), "last": last_detail},
                }
            # 错误验证码：继续等待下一封邮件

        self._relogin_trace(
            "otp_timeout",
            email=email,
            tried=sorted(tried),
            last=last_detail,
        )
        return {
            "ok": False,
            "error": "otp_timeout",
            "detail": {"email": email, "tried": sorted(tried), "last": last_detail},
        }


    def _send_passwordless_login_otp(self, session, device_id: str, headers: dict) -> tuple[bool, str]:
        """触发无密码邮箱 OTP：优先 passwordless/send-otp，失败再回退 email-otp/send。"""
        auth_base = "https://auth.openai.com"
        otp_headers = dict(headers or {})
        otp_headers["accept"] = "application/json"
        otp_headers["content-type"] = "application/json"
        otp_headers["oai-device-id"] = device_id
        otp_headers.setdefault("referer", f"{auth_base}/log-in/password")
        otp_headers.setdefault("origin", auth_base)

        try:
            resp = session.post(
                f"{auth_base}/api/accounts/passwordless/send-otp",
                headers=otp_headers,
                data=b"",
                timeout=30,
            )
            if getattr(resp, "status_code", None) == 200:
                self._relogin_trace("passwordless_send_otp_ok", path="passwordless/send-otp")
                return True, ""
            detail = (getattr(resp, "text", None) or "")[:200]
            last_error = f"passwordless/send-otp_http_{getattr(resp, 'status_code', 'unknown')}:{detail}"
            self._relogin_trace("passwordless_send_otp_fail", error=last_error)
        except Exception as exc:
            last_error = f"passwordless/send-otp_exception:{exc}"
            self._relogin_trace("passwordless_send_otp_exception", error=last_error)

        # 回退到通用 email-otp/send
        try:
            self._send_login_email_otp(session, device_id, otp_headers)
            self._relogin_trace("passwordless_fallback_email_otp_send", previous_error=last_error)
            return True, last_error
        except Exception as exc:
            self._relogin_trace("passwordless_fallback_failed", error=f"{last_error}; email-otp/send_exception:{exc}")
            return False, f"{last_error}; email-otp/send_exception:{exc}"


    @staticmethod
    def _classify_login_step(
        *,
        page_type: str = "",
        continue_url: str = "",
        current_url: str = "",
        detail: dict | None = None,
    ) -> dict[str, Any]:
        """Align with codex-console: detect password page / email OTP / about-you / auth code."""
        detail = detail if isinstance(detail, dict) else {}
        page = detail.get("page") if isinstance(detail.get("page"), dict) else {}
        resolved_page_type = str(page_type or page.get("type") or "").strip().lower()
        resolved_continue = str(continue_url or detail.get("continue_url") or "").strip()
        resolved_current = str(current_url or "").strip()
        blob = f"{resolved_page_type} {resolved_continue} {resolved_current}".lower()

        auth_code = AccountService._extract_auth_code_from_payload(detail)

        needs_login_password = (
            resolved_page_type == "login_password"
            or "log-in/password" in blob
            or "/login/password" in blob
        )
        needs_email_otp = (
            resolved_page_type in {"email_otp_verification", "email_otp", "email_verification"}
            or "email-verification" in blob
            or "email-otp" in blob
            or "email_otp" in blob
        )
        is_about_you = resolved_page_type == "about_you" or "about-you" in blob
        is_create_account = (
            "create-account" in blob
            or resolved_page_type in {"create_account", "password_registration"}
        ) and not needs_login_password and not needs_email_otp and not is_about_you

        return {
            "page_type": resolved_page_type,
            "continue_url": resolved_continue,
            "current_url": resolved_current,
            "auth_code": auth_code,
            "needs_login_password": needs_login_password,
            "needs_email_otp": needs_email_otp,
            "is_about_you": is_about_you,
            "is_create_account": is_create_account,
        }

    def _authorize_continue_with_email(self, session, device_id: str, email: str, headers: dict, referer: str = "", screen_hint: str = "login_or_signup") -> dict:
        """提交邮箱进入登录态（passwordless 需要）。"""
        auth_base = "https://auth.openai.com"
        continue_headers = dict(headers or {})
        continue_headers["accept"] = "application/json"
        continue_headers["content-type"] = "application/json"
        continue_headers["origin"] = auth_base
        continue_headers["referer"] = referer or f"{auth_base}/log-in"
        continue_headers["oai-device-id"] = device_id
        try:
            from utils.sentinel import build_sentinel_token

            sentinel_val, oai_sc_val = build_sentinel_token(session, device_id, "authorize_continue")
            continue_headers["openai-sentinel-token"] = sentinel_val
            if oai_sc_val:
                session.cookies.set("oai-sc", oai_sc_val, domain=".openai.com")
                session.cookies.set("oai-sc", oai_sc_val, domain=".auth.openai.com")
        except Exception:
            pass

        try:
            resp = session.post(
                f"{auth_base}/api/accounts/authorize/continue",
                headers=continue_headers,
                json={
                    "username": {"kind": "email", "value": email},
                    "screen_hint": str(screen_hint or "login_or_signup").strip() or "login_or_signup",
                },
                timeout=30,
            )
        except Exception as exc:
            return {"ok": False, "error": "authorize_continue_exception", "detail": {"message": str(exc)}}

        data: dict[str, Any] = {}
        try:
            data = resp.json() if resp.text else {}
        except Exception:
            data = {}
        if not isinstance(data, dict):
            data = {}

        if getattr(resp, "status_code", None) != 200:
            self._relogin_trace(
                "authorize_continue_failed",
                email=email,
                status=getattr(resp, "status_code", None),
                detail=data or {"text": (getattr(resp, "text", None) or "")[:300]},
            )
            return {
                "ok": False,
                "error": f"authorize_continue_failed_{getattr(resp, 'status_code', 'unknown')}",
                "detail": data or {"text": (getattr(resp, "text", None) or "")[:300]},
            }
        page = data.get("page") if isinstance(data.get("page"), dict) else {}
        self._relogin_trace(
            "authorize_continue_ok",
            email=email,
            continue_url=str(data.get("continue_url") or ""),
            page_type=str(page.get("type") or ""),
            screen_hint=str(screen_hint or "login_or_signup"),
            detail_keys=sorted(list(data.keys())) if isinstance(data, dict) else [],
        )
        return {"ok": True, "detail": data}

    def _build_login_token_result(
        self,
        session,
        *,
        email: str,
        access_token: str = "",
        refresh_token: str = "",
        id_token: str = "",
        source_type: str = "login",
        user_agent: str = "",
        continue_url: str = "",
        prefer_web_session: bool = True,
    ) -> dict:
        """组装登录结果；优先升级为 chatgpt.com/api/auth/session 完整网页凭证。"""
        from services.register.chatgpt_web_entry import fetch_chatgpt_web_session

        ua = str(user_agent or self._OAUTH_USER_AGENT)
        session_creds: dict[str, Any] = {}
        if prefer_web_session and session is not None:
            try:
                session_creds = fetch_chatgpt_web_session(
                    session,
                    continue_url=continue_url,
                    user_agent=ua,
                    timeout=30,
                )
            except Exception as exc:
                self._relogin_trace(
                    "web_session_fetch_exception",
                    email=email,
                    error=str(exc),
                )
                session_creds = {"ok": False, "error": str(exc)}

        if session_creds.get("ok") and session_creds.get("access_token"):
            self._relogin_trace(
                "web_session_fetch_ok",
                email=email,
                account_id=str(session_creds.get("account_id") or ""),
                has_session_token=bool(session_creds.get("session_token")),
            )
            # session access_token 优先；refresh 可回退 oauth
            access = str(session_creds.get("access_token") or "").strip()
            refresh = str(session_creds.get("refresh_token") or refresh_token or "").strip()
            idt = str(session_creds.get("id_token") or id_token or "").strip()
            jwt_payload = self._decode_jwt_payload(access)
            return {
                "ok": True,
                "email": str(session_creds.get("email") or email).strip(),
                "account_id": str(session_creds.get("account_id") or "").strip(),
                "access_token": access,
                "refresh_token": refresh,
                "id_token": idt,
                "session_token": str(session_creds.get("session_token") or "").strip(),
                "expires_at": session_creds.get("expires_at") or jwt_payload.get("exp"),
                "source_type": "chatgpt_session",
                "raw_session": session_creds.get("raw_session") or {},
            }

        # fallback: oauth / provided tokens
        access_token = str(access_token or "").strip()
        if not access_token:
            return {
                "ok": False,
                "error": "no_access_token",
                "detail": session_creds if isinstance(session_creds, dict) else {},
            }

        user_info: dict[str, Any] = {}
        try:
            me_resp = session.get(
                "https://chatgpt.com/backend-api/me",
                headers={
                    "accept": "application/json",
                    "authorization": f"Bearer {access_token}",
                    "user-agent": ua,
                },
                timeout=30,
            )
            if me_resp.status_code == 200:
                payload = me_resp.json() if me_resp.text else {}
                if isinstance(payload, dict):
                    user_info = payload
        except Exception:
            pass

        jwt_payload = self._decode_jwt_payload(access_token)
        email_from_jwt = str(
            jwt_payload.get("https://api.openai.com/profile", {}).get("email") or ""
        ).strip()
        account_id_from_jwt = str(
            jwt_payload.get("https://api.openai.com/auth", {}).get("chatgpt_account_id") or ""
        ).strip()
        account_info = user_info.get("account") if isinstance(user_info.get("account"), dict) else {}
        self._relogin_trace(
            "web_session_fetch_fallback_oauth",
            email=email,
            account_id=account_id_from_jwt or str(account_info.get("account_id") or ""),
            session_error=str((session_creds or {}).get("error") or ""),
        )
        return {
            "ok": True,
            "email": email_from_jwt or email,
            "account_id": account_id_from_jwt or account_info.get("account_id", ""),
            "access_token": access_token,
            "refresh_token": str(refresh_token or "").strip(),
            "id_token": str(id_token or "").strip(),
            "session_token": "",
            "expires_at": jwt_payload.get("exp"),
            "source_type": source_type,
        }


    def _bootstrap_chatgpt_web_authorize(
        self,
        email: str,
        *,
        screen_hint: str = "login_or_signup",
        event: str = "relogin",
    ) -> dict:
        """续期/重登：纯协议 ChatGPT 官网入口 authorize。"""
        from services.register.chatgpt_web_entry import ChatGPTWebEntry

        proxy = ""
        try:
            proxy = str(config.get_proxy_settings() or "").strip()
        except Exception:
            proxy = ""

        def _log(msg: str) -> None:
            self._relogin_trace("web_entry", email=email, event=event, message=msg)

        entry = ChatGPTWebEntry(
            email,
            proxy=proxy,
            log=_log,
            timeout=30,
            verbose=False,
            screen_hint=screen_hint,
        )
        try:
            result = entry.execute()
        except Exception as exc:
            try:
                entry.close()
            except Exception:
                pass
            return {
                "ok": False,
                "error": f"web_entry_exception:{exc}",
                "detail": {"message": str(exc)},
            }

        if not result.success:
            try:
                entry.close()
            except Exception:
                pass
            return {
                "ok": False,
                "error": "web_entry_failed",
                "detail": {
                    "message": result.error,
                    "authorize_url": result.authorize_url,
                    "final_url": result.final_url,
                },
            }

        return {
            "ok": True,
            "session": result.session,
            "device_id": result.device_id,
            "final_url": result.final_url,
            "page_type": result.page_type,
            "profile": result.profile,
            "authorize_url": result.authorize_url,
            "user_agent": str((result.profile or {}).get("user_agent") or ""),
        }

    def _login_with_email_otp(
        self,
        email: str,
        receive_email: str = "",
        mail_provider_ref: str = "",
        mail_provider_type: str = "",
    ) -> dict:
        """仅邮箱 + 邮箱验证码（passwordless）登录，返回 token 结果。"""
        from curl_cffi import requests
        from urllib.parse import parse_qs, urlparse

        email = str(email or "").strip()
        if not email:
            return {"ok": False, "error": "missing_email", "detail": {}}

        self._relogin_trace(
            "email_otp_begin",
            email=email,
            receive_email=receive_email,
            mail_provider_ref=mail_provider_ref,
            mail_provider_type=mail_provider_type,
            screen_hint="login_or_signup",
            entry="email_otp_via_login_or_signup",
        )

        auth_base = "https://auth.openai.com"
        user_agent = self._OAUTH_USER_AGENT
        platform_oauth_client_id = self._OAUTH_CLIENT_ID
        platform_oauth_redirect_uri = "https://platform.openai.com/auth/callback"
        code_verifier = ""
        session = None

        try:
            boot = self._bootstrap_chatgpt_web_authorize(
                email,
                screen_hint="login_or_signup",
                event="email_otp",
            )
            if not boot.get("ok"):
                return {
                    "ok": False,
                    "error": str(boot.get("error") or "web_entry_failed"),
                    "detail": boot.get("detail") or {},
                }

            session = boot["session"]
            device_id = str(boot.get("device_id") or uuid.uuid4())
            final_url = str(boot.get("final_url") or f"{auth_base}/log-in")
            if boot.get("user_agent"):
                user_agent = str(boot["user_agent"])
            self._relogin_trace(
                "email_otp_authorize",
                email=email,
                status=200,
                final_url=final_url,
                page_type=str(boot.get("page_type") or ""),
                screen_hint="login_or_signup",
                entry="chatgpt_web",
            )

            login_headers = {
                "accept": "application/json",
                "accept-language": "zh-CN,zh;q=0.9",
                "content-type": "application/json",
                "origin": auth_base,
                "priority": "u=1, i",
                "user-agent": user_agent,
                "sec-ch-ua": '"Chromium";v="145", "Google Chrome";v="145", "Not/A)Brand";v="99"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
                "referer": final_url if final_url.startswith(auth_base) else f"{auth_base}/log-in",
                "oai-device-id": device_id,
            }

            continue_result = self._authorize_continue_with_email(
                session,
                device_id,
                email,
                login_headers,
                referer=login_headers["referer"],
                screen_hint="login_or_signup",
            )
            continue_detail = continue_result.get("detail") if isinstance(continue_result.get("detail"), dict) else {}
            if not continue_result.get("ok"):
                # login_hint 有时已足够进入登录态，continue 失败不立刻中断
                self._relogin_trace(
                    "email_otp_continue_soft_fail",
                    email=email,
                    error=str(continue_result.get("error") or ""),
                    detail=continue_detail,
                )

            step = self._classify_login_step(
                detail=continue_detail,
                current_url=final_url,
            )
            # authorize 落地 URL 也纳入判断（login_hint 可能直接落到密码/OTP 页）
            if not step.get("needs_login_password") and not step.get("needs_email_otp") and not step.get("auth_code"):
                step = self._classify_login_step(
                    detail=continue_detail,
                    current_url=final_url,
                    continue_url=str(continue_detail.get("continue_url") or final_url),
                )
            self._relogin_trace(
                "email_otp_step_classified",
                email=email,
                page_type=step.get("page_type"),
                continue_url=step.get("continue_url"),
                current_url=final_url,
                needs_login_password=bool(step.get("needs_login_password")),
                needs_email_otp=bool(step.get("needs_email_otp")),
                is_about_you=bool(step.get("is_about_you")),
                has_auth_code=bool(step.get("auth_code")),
            )

            auth_code = str(step.get("auth_code") or "").strip()
            otp_result: dict[str, Any] = {"ok": False, "auth_code": "", "detail": continue_detail}

            if auth_code:
                self._relogin_trace("email_otp_got_code_before_otp", email=email, auth_code_prefix=auth_code[:8] + "...")
                otp_result = {"ok": True, "auth_code": auth_code, "detail": continue_detail}
            elif step.get("is_about_you") and not step.get("needs_login_password") and not step.get("needs_email_otp"):
                self._relogin_trace(
                    "email_otp_unexpected_about_you",
                    email=email,
                    detail=continue_detail,
                    final_url=final_url,
                )
                return {
                    "ok": False,
                    "error": "unexpected_about_you",
                    "detail": continue_detail or {"url": final_url},
                }
            else:
                # codex-console: 只有落到密码页时，才主动切 passwordless 邮箱验证码
                need_passwordless = bool(step.get("needs_login_password"))
                already_otp = bool(step.get("needs_email_otp"))
                if not need_passwordless and not already_otp:
                    # continue 失败/状态不清时，若 URL 像密码页则仍按密码页处理
                    lowered = final_url.lower()
                    if "log-in/password" in lowered or "/login/password" in lowered:
                        need_passwordless = True
                    elif "email-verification" in lowered or "email-otp" in lowered:
                        already_otp = True

                if need_passwordless:
                    pwd_headers = dict(login_headers)
                    pwd_headers["referer"] = f"{auth_base}/log-in/password"
                    self._relogin_trace(
                        "email_otp_switch_passwordless_from_password_page",
                        email=email,
                        referer=pwd_headers["referer"],
                    )
                    send_ok, send_detail = self._send_passwordless_login_otp(session, device_id, pwd_headers)
                    self._relogin_trace(
                        "email_otp_send_result",
                        email=email,
                        ok=send_ok,
                        detail=send_detail or "",
                        trigger="login_password",
                    )
                    if not send_ok:
                        return {
                            "ok": False,
                            "error": "passwordless_send_otp_failed",
                            "detail": {"message": send_detail, "email": email, "page": "login_password"},
                        }
                    send_otp = False
                elif already_otp:
                    self._relogin_trace(
                        "email_otp_already_on_verification_page",
                        email=email,
                        continue_url=step.get("continue_url") or final_url,
                    )
                    # authorize 已落到验证码页时，OpenAI 通常已自动发码；先收码，失败后再补发
                    send_otp = False
                else:
                    self._relogin_trace(
                        "email_otp_unexpected_step",
                        email=email,
                        page_type=step.get("page_type"),
                        continue_url=step.get("continue_url"),
                        final_url=final_url,
                        detail=continue_detail,
                    )
                    return {
                        "ok": False,
                        "error": "unexpected_login_step",
                        "detail": {
                            "email": email,
                            "page_type": step.get("page_type"),
                            "continue_url": step.get("continue_url"),
                            "final_url": final_url,
                            "continue": continue_detail,
                        },
                    }

                otp_headers = dict(login_headers)
                otp_headers["referer"] = f"{auth_base}/email-verification"
                otp_result = self._complete_email_otp_login(
                    session=session,
                    device_id=device_id,
                    email=email,
                    headers=otp_headers,
                    send_otp=send_otp,
                    receive_email=receive_email,
                    mail_provider_ref=mail_provider_ref,
                    mail_provider_type=mail_provider_type,
                )
            if not otp_result.get("ok"):
                err = str(otp_result.get("error") or "")
                self._relogin_trace(
                    "email_otp_complete_first_fail",
                    email=email,
                    error=err,
                    detail=otp_result.get("detail"),
                )
                if err in {
                    "otp_max_check_attempts",
                    "rate_limit_exceeded",
                    "otp_mail_unavailable",
                    "account_deactivated",
                    "account_deleted",
                    "user_banned",
                    "account_banned",
                    "unexpected_about_you",
                    "otp_no_auth_code",
                }:
                    return otp_result
                # 首轮未发出/漏信时再补一次通用 send
                self._relogin_trace("email_otp_resend_email_otp", email=email)
                self._send_login_email_otp(session, device_id, otp_headers)
                otp_result = self._complete_email_otp_login(
                    session=session,
                    device_id=device_id,
                    email=email,
                    headers=otp_headers,
                    send_otp=False,
                    receive_email=receive_email,
                    mail_provider_ref=mail_provider_ref,
                    mail_provider_type=mail_provider_type,
                )
                if not otp_result.get("ok"):
                    self._relogin_trace(
                        "email_otp_complete_second_fail",
                        email=email,
                        error=str(otp_result.get("error") or ""),
                        detail=otp_result.get("detail"),
                    )
                    return otp_result

            auth_code = str(otp_result.get("auth_code") or "").strip()
            if not auth_code:
                self._relogin_trace(
                    "email_otp_no_auth_code",
                    email=email,
                    detail=otp_result.get("detail") or {},
                )
                return {
                    "ok": False,
                    "error": "otp_no_auth_code",
                    "detail": otp_result.get("detail") or {},
                }

            # 优先走 chatgpt session（完整 claims，便于 Agent Identity）
            continue_url = ""
            detail = otp_result.get("detail") if isinstance(otp_result.get("detail"), dict) else {}
            continue_url = str(detail.get("continue_url") or "").strip()
            if continue_url and "code=" not in continue_url and auth_code:
                # 某些响应只给中间页，尝试拼 callback
                pass
            if (not continue_url) and auth_code:
                continue_url = (
                    f"https://chatgpt.com/api/auth/callback/openai?code={auth_code}"
                )

            session_first = self._build_login_token_result(
                session,
                email=email,
                access_token="",
                refresh_token="",
                id_token="",
                source_type="email_otp",
                user_agent=user_agent,
                continue_url=continue_url,
                prefer_web_session=True,
            )
            if session_first.get("ok") and session_first.get("access_token") and session_first.get("account_id"):
                self._relogin_trace(
                    "email_otp_success",
                    email=session_first.get("email") or email,
                    account_id=session_first.get("account_id"),
                    expires_at=session_first.get("expires_at"),
                    has_refresh_token=bool(session_first.get("refresh_token")),
                    has_session_token=bool(session_first.get("session_token")),
                    source_type=session_first.get("source_type"),
                )
                return session_first

            self._relogin_trace(
                "email_otp_token_exchange_begin",
                email=email,
                auth_code_prefix=auth_code[:8] + "...",
            )
            platform_base = "https://platform.openai.com"
            platform_auth0_client = "eyJuYW1lIjoiYXV0aDAtc3BhLWpzIiwidmVyc2lvbiI6IjEuMjEuMCJ9"
            token_resp = session.post(
                f"{auth_base}/api/accounts/oauth/token",
                headers={
                    "accept": "*/*",
                    "accept-language": "zh-CN,zh;q=0.9",
                    "auth0-client": platform_auth0_client,
                    "cache-control": "no-cache",
                    "content-type": "application/json",
                    "origin": platform_base,
                    "pragma": "no-cache",
                    "priority": "u=1, i",
                    "referer": f"{platform_base}/",
                    "sec-ch-ua": '"Chromium";v="145", "Google Chrome";v="145", "Not/A)Brand";v="99"',
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": '"Windows"',
                    "sec-fetch-dest": "empty",
                    "sec-fetch-mode": "cors",
                    "sec-fetch-site": "same-site",
                    "user-agent": user_agent,
                },
                json={
                    "client_id": platform_oauth_client_id,
                    "code_verifier": code_verifier,
                    "grant_type": "authorization_code",
                    "code": auth_code,
                    "redirect_uri": platform_oauth_redirect_uri,
                },
                verify=False,
                timeout=60,
            )
            token_data: dict[str, Any] = {}
            try:
                token_data = token_resp.json() if token_resp.text else {}
            except Exception:
                token_data = {}
            if token_resp.status_code != 200 or not token_data.get("access_token"):
                self._relogin_trace(
                    "email_otp_token_exchange_failed",
                    email=email,
                    status=token_resp.status_code,
                    detail=token_data,
                )
                return {"ok": False, "error": "token_exchange_failed", "detail": token_data}

            result = self._build_login_token_result(
                session,
                email=email,
                access_token=str(token_data.get("access_token") or "").strip(),
                refresh_token=str(token_data.get("refresh_token") or "").strip(),
                id_token=str(token_data.get("id_token") or "").strip(),
                source_type="email_otp",
                user_agent=user_agent,
                continue_url=continue_url,
                prefer_web_session=True,
            )
            self._relogin_trace(
                "email_otp_success",
                email=result.get("email") or email,
                account_id=result.get("account_id"),
                expires_at=result.get("expires_at"),
                has_refresh_token=bool(result.get("refresh_token")),
                has_session_token=bool(result.get("session_token")),
                source_type=result.get("source_type"),
            )
            return result
        finally:
            try:
                if session is not None:
                    session.close()
            except Exception:
                pass

    def _login_with_password(
        self,
        email: str,
        password: str,
        receive_email: str = "",
        mail_provider_ref: str = "",
        mail_provider_type: str = "",
    ) -> dict:
        """通过邮箱+密码登录，返回 {access_token, refresh_token, id_token, ...}"""
        from curl_cffi import requests
        
        self._relogin_trace(
            "password_login_begin",
            email=email,
            receive_email=receive_email,
            mail_provider_ref=mail_provider_ref,
            mail_provider_type=mail_provider_type,
            screen_hint="login_or_signup",
            entry="password",
        )
        # 常量
        auth_base = "https://auth.openai.com"
        platform_oauth_audience = "https://api.openai.com/v1"
        platform_auth0_client = "eyJuYW1lIjoiYXV0aDAtc3BhLWpzIiwidmVyc2lvbiI6IjEuMjEuMCJ9"
        platform_oauth_client_id = self._OAUTH_CLIENT_ID
        platform_oauth_redirect_uri = "https://platform.openai.com/auth/callback"
        user_agent = self._OAUTH_USER_AGENT
        
        session = None
        try:
            device_id = str(uuid.uuid4())
            code_verifier = ""
            boot = self._bootstrap_chatgpt_web_authorize(
                email,
                screen_hint="login_or_signup",
                event="password",
            )
            if not boot.get("ok"):
                return {
                    "ok": False,
                    "error": str(boot.get("error") or "web_entry_failed"),
                    "detail": boot.get("detail") or {},
                }
            session = boot["session"]
            device_id = str(boot.get("device_id") or device_id)
            final_url = str(boot.get("final_url") or f"{auth_base}/log-in")
            if boot.get("user_agent"):
                user_agent = str(boot["user_agent"])
            self._relogin_trace(
                "password_authorize",
                email=email,
                status=200,
                final_url=final_url,
                page_type=str(boot.get("page_type") or ""),
                screen_hint="login_or_signup",
                entry="chatgpt_web",
            )

            # ③ 提交密码验证
            login_headers = {
                "accept": "application/json",
                "accept-language": "zh-CN,zh;q=0.9",
                "content-type": "application/json",
                "origin": auth_base,
                "priority": "u=1, i",
                "user-agent": user_agent,
                "sec-ch-ua": '"Chromium";v="145", "Google Chrome";v="145", "Not/A)Brand";v="99"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
                "referer": f"{auth_base}/email-verification",
                "oai-device-id": device_id,
            }
            
            # 添加 sentinel token
            try:
                from utils.sentinel import build_sentinel_token
                sentinel_val, oai_sc_val = build_sentinel_token(session, device_id, "password_verify")
                login_headers["openai-sentinel-token"] = sentinel_val
                if oai_sc_val:
                    session.cookies.set("oai-sc", oai_sc_val, domain=".openai.com")
            except Exception:
                pass
            
            login_resp = session.post(
                f"{auth_base}/api/accounts/password/verify",
                headers=login_headers,
                json={"password": password},
                timeout=30,
            )
            
            login_data = {}
            try:
                login_data = login_resp.json() if login_resp.text else {}
            except Exception:
                pass
            
            page_info = login_data.get("page") if isinstance(login_data.get("page"), dict) else {}
            self._relogin_trace(
                "password_verify_result",
                email=email,
                status=login_resp.status_code,
                continue_url=str(login_data.get("continue_url") or ""),
                page_type=str(page_info.get("type") or ""),
                has_code=bool(self._extract_auth_code_from_payload(login_data if isinstance(login_data, dict) else {})),
            )
            if login_resp.status_code != 200:
                error_code = login_data.get("error", {}).get("code", "")
                error_msg = login_data.get("error", {}).get("message", "")
                self._relogin_trace(
                    "password_verify_failed",
                    email=email,
                    status=login_resp.status_code,
                    error_code=error_code,
                    error_msg=error_msg,
                    detail=login_data,
                )
                if error_code == "unsupported_country_region_territory":
                    return {"ok": False, "error": "unsupported_country_region_territory", "detail": login_data}
                elif error_code == "invalid_state":
                    return {"ok": False, "error": "invalid_state", "detail": login_data}
                elif "Invalid credentials" in error_msg or "wrong password" in error_msg.lower():
                    return {"ok": False, "error": "invalid_password", "detail": login_data}
                return {"ok": False, "error": f"password_verify_failed_{login_resp.status_code}", "detail": login_data}
            
            # 获取 authorization code
            continue_url = str(login_data.get("continue_url") or "").strip()
            auth_code = ""
            if continue_url:
                from urllib.parse import parse_qs, urlparse
                parsed_params = parse_qs(urlparse(continue_url).query)
                auth_code = str((parsed_params.get("code") or [""])[0]).strip()
            
            # ─── 处理邮箱 OTP 验证 ──────────────────────────
            if not auth_code:
                page_type = ""
                page_info = login_data.get("page")
                if isinstance(page_info, dict):
                    page_type = str(page_info.get("type") or "")
                
                needs_otp = (
                    page_type == "email_otp_verification"
                    or "email-verification" in continue_url
                    or "email-otp" in continue_url
                    or "email_otp" in page_type
                )
                self._relogin_trace(
                    "password_needs_otp",
                    email=email,
                    needs_otp=needs_otp,
                    page_type=page_type,
                    continue_url=continue_url,
                )
                if needs_otp:
                    otp_result = self._complete_email_otp_login(
                        session=session,
                        device_id=device_id,
                        email=email,
                        headers=login_headers,
                        receive_email=receive_email,
                        mail_provider_ref=mail_provider_ref,
                        mail_provider_type=mail_provider_type,
                    )
                    if not otp_result.get("ok"):
                        return otp_result
                    auth_code = str(otp_result.get("auth_code") or "").strip()
                    if not auth_code:
                        return {
                            "ok": False,
                            "error": "otp_no_auth_code",
                            "detail": otp_result.get("detail") or login_data,
                        }
                else:
                    return {"ok": False, "error": "no_auth_code", "detail": login_data}
            
            # ④ 用 code 换 token (使用 Platform Client + code_verifier，与注册流程相同)
            platform_base = "https://platform.openai.com"
            token_resp = session.post(
                f"{auth_base}/api/accounts/oauth/token",
                headers={
                    "accept": "*/*",
                    "accept-language": "zh-CN,zh;q=0.9",
                    "auth0-client": platform_auth0_client,
                    "cache-control": "no-cache",
                    "content-type": "application/json",
                    "origin": platform_base,
                    "pragma": "no-cache",
                    "priority": "u=1, i",
                    "referer": f"{platform_base}/",
                    "sec-ch-ua": '"Chromium";v="145", "Google Chrome";v="145", "Not/A)Brand";v="99"',
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": '"Windows"',
                    "sec-fetch-dest": "empty",
                    "sec-fetch-mode": "cors",
                    "sec-fetch-site": "same-site",
                    "user-agent": user_agent,
                },
                json={
                    "client_id": platform_oauth_client_id,
                    "code_verifier": code_verifier,
                    "grant_type": "authorization_code",
                    "code": auth_code,
                    "redirect_uri": platform_oauth_redirect_uri,
                },
                verify=False,
                timeout=60,
            )
            
            token_data = {}
            try:
                token_data = token_resp.json() if token_resp.text else {}
            except Exception:
                pass
            
            if token_resp.status_code != 200 or not token_data.get("access_token"):
                self._relogin_trace(
                    "password_token_exchange_failed",
                    email=email,
                    status=token_resp.status_code,
                    detail=token_data,
                )
                return {"ok": False, "error": "token_exchange_failed", "detail": token_data}

            self._relogin_trace(
                "password_token_exchange_ok",
                email=email,
                has_refresh_token=bool(token_data.get("refresh_token")),
            )
            
            access_token = str(token_data.get("access_token") or "").strip()
            refresh_token = str(token_data.get("refresh_token") or "").strip()
            id_token = str(token_data.get("id_token") or "").strip()

            continue_url = ""
            try:
                continue_url = str(login_data.get("continue_url") or "").strip()
            except Exception:
                continue_url = ""
            if (not continue_url) and access_token:
                # still try session upgrade using existing cookies / homepage
                continue_url = ""

            result = self._build_login_token_result(
                session,
                email=email,
                access_token=access_token,
                refresh_token=refresh_token,
                id_token=id_token,
                source_type="password",
                user_agent=user_agent,
                continue_url=continue_url,
                prefer_web_session=True,
            )
            if not result.get("ok"):
                return result
            self._relogin_trace(
                "password_login_success",
                email=result.get("email") or email,
                account_id=result.get("account_id"),
                expires_at=result.get("expires_at"),
                has_refresh_token=bool(result.get("refresh_token")),
                has_session_token=bool(result.get("session_token")),
                source_type=result.get("source_type"),
            )
            return result
        
        finally:
            try:
                if session is not None:
                    session.close()
            except Exception:
                pass

    def list_expiring_access_tokens(self, limit: int | None = None) -> list[str]:
        """即将过期的 access_token。

        含两类：
        - 有 refresh_token，可走 OAuth 刷新
        - 无 RT 但有邮箱，可走重登兜底

        默认按 exp 升序 + token 稳定 jitter 排序，优先最紧急的；
        limit 用于 watcher 错峰，避免同一轮打满全库。
        """
        with self._lock:
            ranked: list[tuple[int, int, str]] = []
            for account in self._accounts.values():
                token = str(account.get("access_token") or "").strip()
                if not token or not self._token_needs_refresh(token):
                    continue
                has_rt = bool(str(account.get("refresh_token") or "").strip())
                has_email = bool(str(account.get("email") or "").strip())
                if not (has_rt or has_email):
                    continue
                exp = self._jwt_exp(token) or 0
                # 稳定抖动：同一 exp 附近打散顺序，避免每轮完全同一批
                jitter = zlib.crc32(token.encode("utf-8")) & 0xFFFF
                ranked.append((exp, jitter, token))
        ranked.sort(key=lambda item: (item[0], item[1], item[2]))
        tokens = [token for _, _, token in ranked]
        if limit is None:
            limit = self._EXPIRING_TOKEN_BATCH_SIZE
        if limit >= 0:
            tokens = tokens[: int(limit)]
        return tokens

    def list_refresh_token_keepalive_tokens(self) -> list[str]:
        now = datetime.now(timezone.utc)
        due_items: list[tuple[datetime, str]] = []
        with self._lock:
            for account in self._accounts.values():
                due_at = self._refresh_token_keepalive_due_at(account, now)
                token = str(account.get("access_token") or "").strip()
                if due_at is not None and token:
                    due_items.append((due_at, token))
        due_items.sort(key=lambda item: item[0])
        return [token for _, token in due_items[: self._REFRESH_TOKEN_KEEPALIVE_BATCH_SIZE]]

    def keepalive_refresh_tokens(self, access_tokens: list[str]) -> dict[str, Any]:
        access_tokens = list(dict.fromkeys(token for token in access_tokens if token))
        if not access_tokens:
            return {"refreshed": 0, "errors": [], "items": self.list_accounts()}

        refreshed = 0
        errors = []
        for access_token in access_tokens:
            before = self.resolve_access_token(access_token)
            after = self.refresh_access_token(before, force=True, event="refresh_token_keepalive")
            account = self.get_account(after)
            if account and str(account.get("last_token_refresh_error") or "").strip():
                errors.append({
                    "token": anonymize_token(before),
                    "error": str(account.get("last_token_refresh_error") or "refresh token failed"),
                })
                continue
            if account:
                refreshed += 1

        return {
            "refreshed": refreshed,
            "errors": errors,
            "items": self.list_accounts(),
            "relogined": 0,
        }

    def list_tokens(self) -> list[str]:
        with self._lock:
            return list(self._accounts)

    def _list_ready_candidate_tokens(
            self,
            excluded_tokens: set[str] | None = None,
            plan_type: str | None = None,
            source_type: str | None = None,
            plan_types: set[str] | tuple[str, ...] | None = None,
    ) -> list[str]:
        excluded = set(excluded_tokens or set())
        return [
            token
            for item in self._accounts.values()
            if self._is_image_account_available(item)
               and self._account_matches_plan_type(item, plan_type)
               and self._account_matches_any_plan_type(item, plan_types)
               and self._account_matches_source_type(item, source_type)
               and (token := item.get("access_token") or "")
               and token not in excluded
        ]

    def _list_available_candidate_tokens(
            self,
            excluded_tokens: set[str] | None = None,
            plan_type: str | None = None,
            source_type: str | None = None,
            plan_types: set[str] | tuple[str, ...] | None = None,
    ) -> list[str]:
        max_concurrency = max(1, int(config.image_account_concurrency or 1))
        return [
            token
            for token in self._list_ready_candidate_tokens(excluded_tokens, plan_type, source_type, plan_types)
            if int(self._image_inflight.get(token, 0)) < max_concurrency
        ]

    def _acquire_next_candidate_token(
            self,
            excluded_tokens: set[str] | None = None,
            plan_type: str | None = None,
            source_type: str | None = None,
            plan_types: set[str] | tuple[str, ...] | None = None,
    ) -> str:
        with self._image_slot_condition:
            while True:
                if not self._list_ready_candidate_tokens(excluded_tokens, plan_type, source_type, plan_types):
                    raise RuntimeError(
                        f"no available {plan_type or source_type or ''} image quota".replace("  ", " ").strip()
                        if plan_type or source_type else "no available image quota"
                    )
                tokens = self._list_available_candidate_tokens(excluded_tokens, plan_type, source_type, plan_types)
                if tokens:
                    access_token = tokens[self._index % len(tokens)]
                    self._index += 1
                    self._image_inflight[access_token] = int(self._image_inflight.get(access_token, 0)) + 1
                    return access_token
                self._image_slot_condition.wait(timeout=1.0)

    def release_image_slot(self, access_token: str) -> None:
        if not access_token:
            return
        with self._image_slot_condition:
            access_token = self._resolve_access_token_locked(access_token)
            current_inflight = int(self._image_inflight.get(access_token, 0))
            if current_inflight <= 1:
                self._image_inflight.pop(access_token, None)
            else:
                self._image_inflight[access_token] = current_inflight - 1
            self._image_slot_condition.notify_all()

    def get_available_access_token(
            self,
            plan_type: str | None = None,
            source_type: str | None = None,
            plan_types: set[str] | tuple[str, ...] | None = None,
    ) -> str:
        """从候选池中获取一个可用的图片生图 token。

        基于本地缓存做初筛，然后通过 fetch_remote_info 做远程验证（token 有效性、配额等）。
        限制最大尝试次数防止 token rotation 导致无限循环。
        """
        max_attempts = 20  # 防止无限循环
        attempted_tokens: set[str] = set()
        for _attempt in range(max_attempts):
            access_token = self._acquire_next_candidate_token(
                excluded_tokens=attempted_tokens,
                plan_type=plan_type,
                source_type=source_type,
                plan_types=plan_types,
            )
            attempted_tokens.add(access_token)
            try:
                account = self.fetch_remote_info(access_token, "get_available_access_token")
            except Exception:
                self.release_image_slot(access_token)
                continue
            # fetch_remote_info 内部可能因 token rotation 导致 access_token 变化，
            # 把新 token 也加入排除列表，防止重复尝试
            resolved = str((account or {}).get("access_token") or "")
            if resolved and resolved != access_token:
                attempted_tokens.add(resolved)
            if (
                    self._is_image_account_available(account or {})
                    and self._account_matches_plan_type(account or {}, plan_type)
                    and self._account_matches_any_plan_type(account or {}, plan_types)
                    and self._account_matches_source_type(account or {}, source_type)
            ):
                return str((account or {}).get("access_token") or access_token)
            self.release_image_slot(access_token)
        raise RuntimeError(
            f"no available {plan_type or source_type or ''} image quota (tried {len(attempted_tokens)} tokens)".replace("  ", " ").strip()
            if plan_type or source_type else f"no available image quota (tried {len(attempted_tokens)} tokens)"
        )

    def get_text_access_token(self, excluded_tokens: set[str] | None = None) -> str:
        excluded = set(excluded_tokens or set())
        with self._lock:
            candidates = [
                token
                for account in self._accounts.values()
                if account.get("status") not in {"禁用", "异常"}
                   and (token := account.get("access_token") or "")
                   and token not in excluded
            ]
            if not candidates:
                return ""
            access_token = candidates[self._index % len(candidates)]
            self._index += 1
        return self.refresh_access_token(access_token, event="get_text_access_token") or access_token

    def mark_text_used(self, access_token: str) -> None:
        if not access_token:
            return
        with self._lock:
            access_token = self._resolve_access_token_locked(access_token)
            current = self._accounts.get(access_token)
            if current is None:
                return
            next_item = dict(current)
            next_item["last_used_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            account = self._normalize_account(next_item)
            if account is None:
                return
            self._accounts[access_token] = account
            self._save_accounts()

    def remove_invalid_token(self, access_token: str, event: str, quiet: bool = False) -> bool:
        if not config.auto_remove_invalid_accounts:
            self.update_account(access_token, {"status": "异常", "quota": 0}, quiet=quiet)
            return False
        removed = bool(self.delete_accounts([access_token])["removed"])
        if removed:
            log_service.add(LOG_TYPE_ACCOUNT, "自动移除异常账号",
                            {"source": event, "token": anonymize_token(access_token)})
        elif access_token:
            self.update_account(access_token, {"status": "异常", "quota": 0}, quiet=quiet)
        return removed

    def get_account(self, access_token: str) -> dict | None:
        if not access_token:
            return None
        with self._lock:
            access_token = self._resolve_access_token_locked(access_token)
            account = self._accounts.get(access_token)
            return dict(account) if account else None

    def list_accounts(self) -> list[dict]:
        """返回所有账号的副本，并为每个账号附加当前图片在途数 image_inflight。

        image_inflight 为内存态并发计数(账号正在生成、尚未结束的图片数)。号池空闲时
        若某账号该值持续 > 0，说明其并发槽位泄漏、已被静默排除出调度，可借此在 UI 上诊断。
        """
        with self._lock:
            result = []
            for item in self._accounts.values():
                account = dict(item)
                token = account.get("access_token") or ""
                account["image_inflight"] = int(self._image_inflight.get(token, 0))
                result.append(account)
            return result

    def list_limited_tokens(self) -> list[str]:
        with self._lock:
            return [
                token
                for item in self._accounts.values()
                if item.get("status") == "限流"
                   and (token := item.get("access_token") or "")
            ]

    def list_normal_tokens(self) -> list[str]:
        with self._lock:
            return [
                token
                for item in self._accounts.values()
                if item.get("status") == "正常"
                   and (token := item.get("access_token") or "")
            ]

    @staticmethod
    def _account_payload_token(item: dict) -> str:
        return str(item.get("access_token") or item.get("accessToken") or "").strip()

    @staticmethod
    def _prepare_account_payload(item: dict) -> dict | None:
        if not isinstance(item, dict):
            return None
        access_token = AccountService._account_payload_token(item)
        if not access_token:
            return None
        payload = dict(item)
        payload.pop("accessToken", None)
        payload["access_token"] = access_token
        # CPA/Codex 导出文件里的 `type=codex` 是导出格式，不是号池套餐类型。
        if str(payload.get("type") or "").strip().lower() == "codex":
            payload["export_type"] = "codex"
            payload["source_type"] = "codex"
            payload.pop("type", None)
        if str(payload.get("export_type") or "").strip().lower() == "codex":
            payload["source_type"] = "codex"
        if payload.get("plan_type") and not payload.get("type"):
            payload["type"] = str(payload.get("plan_type") or "").strip()
        return payload

    def add_account_items(self, items: list[dict]) -> dict:
        payloads = [
            payload
            for item in items
            if (payload := self._prepare_account_payload(item)) is not None
        ]
        return self._add_account_payloads(payloads)

    def add_accounts(self, tokens: list[str], source_type: str = "web") -> dict:
        tokens = list(dict.fromkeys(token for token in tokens if token))
        if not tokens:
            return {"added": 0, "skipped": 0, "items": self.list_accounts()}
        return self._add_account_payloads([
            {"access_token": token, "source_type": self._normalize_source_type(source_type)}
            for token in tokens
        ])

    def _add_account_payloads(self, payloads: list[dict]) -> dict:
        deduped: dict[str, dict] = {}
        for payload in payloads:
            if not isinstance(payload, dict):
                continue
            access_token = self._account_payload_token(payload)
            if not access_token:
                continue
            current = deduped.get(access_token, {})
            deduped[access_token] = {**current, **payload, "access_token": access_token}

        if not deduped:
            return {"added": 0, "skipped": 0, "items": self.list_accounts()}

        with self._lock:
            added = 0
            skipped = 0
            for access_token, payload in deduped.items():
                current = self._accounts.get(access_token)
                if current is None:
                    added += 1
                    self._cumulative_total += 1
                    self._save_cumulative_total()
                    current = {"created_at": self._now()}
                else:
                    skipped += 1
                incoming = dict(payload)
                if not incoming.get("created_at"):
                    incoming.pop("created_at", None)
                account = self._normalize_account(
                    {
                        **current,
                        **incoming,
                        "access_token": access_token,
                        "type": str(incoming.get("type") or current.get("type") or "free"),
                    }
                )
                if account is not None:
                    self._accounts[access_token] = account
            self._save_accounts()
            items = [dict(item) for item in self._accounts.values()]
            log_service.add(LOG_TYPE_ACCOUNT, f"新增 {added} 个账号，跳过 {skipped} 个",
                            {"added": added, "skipped": skipped})
        return {"added": added, "skipped": skipped, "items": items}

    def delete_accounts(self, tokens: list[str]) -> dict:
        target_set = set(token for token in tokens if token)
        if not target_set:
            return {"removed": 0, "items": self.list_accounts()}
        with self._lock:
            target_set = {self._resolve_access_token_locked(token) for token in target_set if token}
            removed = sum(self._accounts.pop(token, None) is not None for token in target_set)
            for token in target_set:
                self._image_inflight.pop(token, None)
            self._token_aliases = {
                old: new
                for old, new in self._token_aliases.items()
                if old not in target_set and new not in target_set
            }
            if removed:
                if self._accounts:
                    self._index %= len(self._accounts)
                else:
                    self._index = 0
                self._save_accounts()
                log_service.add(LOG_TYPE_ACCOUNT, f"删除 {removed} 个账号", {"removed": removed})
            items = [dict(item) for item in self._accounts.values()]
        return {"removed": removed, "items": items}

    def update_account(self, access_token: str, updates: dict, quiet: bool = False) -> dict | None:
        if not access_token:
            return None
        with self._lock:
            access_token = self._resolve_access_token_locked(access_token)
            current = self._accounts.get(access_token)
            if current is None:
                return None
            account = self._normalize_account({**current, **updates, "access_token": access_token})
            if account is None:
                return None
            if account.get("status") == "限流" and config.auto_remove_rate_limited_accounts:
                self._accounts.pop(access_token, None)
                self._save_accounts()
                log_service.add(LOG_TYPE_ACCOUNT, "自动移除限流账号", {"token": anonymize_token(access_token)})
                return None
            self._accounts[access_token] = account
            self._save_accounts()
            if not quiet:
                log_service.add(LOG_TYPE_ACCOUNT, "更新账号",
                                {"token": anonymize_token(access_token), "status": account.get("status")})
            return dict(account)
        return None

    def _record_refresh_success(self, access_token: str) -> None:
        with self._lock:
            access_token = self._resolve_access_token_locked(access_token)
            current = self._accounts.get(access_token)
            if current is None:
                return
            next_item = dict(current)
            next_item["invalid_count"] = 0
            next_item["last_invalid_at"] = None
            next_item["last_refresh_error"] = None
            next_item["last_refresh_error_at"] = None
            account = self._normalize_account(next_item)
            if account is not None:
                self._accounts[access_token] = account

    def _should_defer_invalid_token(self, account: dict | None, now: datetime) -> bool:
        if not isinstance(account, dict):
            return False
        created_at = self._parse_time(account.get("created_at"))
        if created_at is not None and (now - created_at).total_seconds() < self._NEW_ACCOUNT_INVALID_GRACE_SECONDS:
            return True
        last_invalid_at = self._parse_time(account.get("last_invalid_at"))
        invalid_count = int(account.get("invalid_count") or 0)
        if invalid_count <= 1:
            return True
        if last_invalid_at is not None and (now - last_invalid_at).total_seconds() < self._INVALID_CONFIRM_SECONDS:
            return True
        return False

    def _record_invalid_token_seen(
        self,
        access_token: str,
        event: str,
        error: str,
        defer_invalid_removal: bool = True,
    ) -> bool:
        now = datetime.now(timezone.utc)
        with self._lock:
            access_token = self._resolve_access_token_locked(access_token)
            current = self._accounts.get(access_token)
            if current is None:
                return True
            should_defer = defer_invalid_removal and self._should_defer_invalid_token(current, now)
            next_item = dict(current)
            next_item["invalid_count"] = int(next_item.get("invalid_count") or 0) + 1
            next_item["last_invalid_at"] = now.isoformat()
            next_item["last_refresh_error"] = str(error or "invalid access token")
            next_item["last_refresh_error_at"] = now.isoformat()
            account = self._normalize_account(next_item)
            if account is not None:
                self._accounts[access_token] = account
                self._save_accounts()
            if should_defer:
                log_service.add(
                    LOG_TYPE_ACCOUNT,
                    "暂缓标记异常账号",
                    {"source": event, "token": anonymize_token(access_token), "error": str(error or "")},
                )
                return False
        return True

    def mark_image_result(self, access_token: str, success: bool) -> dict | None:
        if not access_token:
            return None
        self.release_image_slot(access_token)
        with self._lock:
            access_token = self._resolve_access_token_locked(access_token)
            current = self._accounts.get(access_token)
            if current is None:
                return None
            next_item = dict(current)
            next_item["last_used_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if success:
                next_item["success"] = int(next_item.get("success") or 0) + 1
                next_item["quota"] = max(0, int(next_item.get("quota") or 0) - 1)
                if next_item["quota"] == 0:
                    next_item["status"] = "限流"
                    next_item["restore_at"] = next_item.get("restore_at") or None
                elif next_item.get("status") == "限流":
                    next_item["status"] = "正常"
            else:
                next_item["fail"] = int(next_item.get("fail") or 0) + 1
            account = self._normalize_account(next_item)
            if account is None:
                return None
            if account.get("status") == "限流" and config.auto_remove_rate_limited_accounts:
                self._accounts.pop(access_token, None)
                self._save_accounts()
                log_service.add(LOG_TYPE_ACCOUNT, "自动移除限流账号", {"token": anonymize_token(access_token)})
                return None
            self._accounts[access_token] = account
            self._save_accounts()
            return dict(account)
        return None

    def fetch_remote_info(
        self,
        access_token: str,
        event: str = "fetch_remote_info",
        defer_invalid_removal: bool = True,
    ) -> dict[str, Any] | None:
        if not access_token:
            raise ValueError("access_token is required")

        active_token = self.refresh_access_token(access_token, event=f"{event}:preflight") or access_token
        try:
            from services.openai_backend_api import InvalidAccessTokenError, OpenAIBackendAPI
            backend = OpenAIBackendAPI(active_token)
            try:
                result = backend.get_user_info()
            finally:
                backend.close()
        except InvalidAccessTokenError as exc:
            refreshed_token = self.refresh_access_token(active_token, force=True, event=f"{event}:invalid_access_token")
            if refreshed_token and refreshed_token != active_token:
                try:
                    backend = OpenAIBackendAPI(refreshed_token)
                    try:
                        result = backend.get_user_info()
                    finally:
                        backend.close()
                except InvalidAccessTokenError as retry_exc:
                    if self._record_invalid_token_seen(
                        refreshed_token,
                        event,
                        str(retry_exc),
                        defer_invalid_removal=defer_invalid_removal,
                    ):
                        self.remove_invalid_token(refreshed_token, event)
                    raise
                active_token = refreshed_token
            else:
                if self._record_invalid_token_seen(
                    active_token,
                    event,
                    str(exc),
                    defer_invalid_removal=defer_invalid_removal,
                ):
                    self.remove_invalid_token(active_token, event)
                raise
        self._record_refresh_success(active_token)
        return self.update_account(active_token, result)

    # ---- 刷新进度追踪 ----

    def init_refresh_progress(self, progress_id: str, total: int) -> None:
        """初始化刷新进度记录。"""
        with self._refresh_progress_lock:
            self._refresh_progress[progress_id] = {
                "total": total,
                "processed": 0,
                "done": False,
                "error": None,
                "status_counts": {"正常": 0, "限流": 0, "异常": 0, "禁用": 0},
                "total_quota": 0,
            }

    def update_refresh_progress(self, progress_id: str, token: str) -> None:
        """刷新单个账号后，更新进度计数。"""
        account = self.get_account(token)
        status = str(account.get("status") or "正常").strip() if account else "正常"
        quota = max(0, int(account.get("quota") or 0)) if account else 0

        with self._refresh_progress_lock:
            progress = self._refresh_progress.get(progress_id)
            if progress is None:
                return
            progress["processed"] += 1
            progress["status_counts"][status] = progress["status_counts"].get(status, 0) + 1
            progress["total_quota"] += quota

    def finish_refresh_progress(self, progress_id: str, result: dict | None = None, error: str | None = None) -> None:
        """标记刷新完成。"""
        with self._refresh_progress_lock:
            progress = self._refresh_progress.get(progress_id)
            if progress is None:
                return
            progress["done"] = True
            progress["result"] = result
            if error:
                progress["error"] = error

    def get_refresh_progress(self, progress_id: str) -> dict | None:
        """查询刷新进度。"""
        with self._refresh_progress_lock:
            progress = self._refresh_progress.get(progress_id)
            return dict(progress) if progress else None

    def clean_refresh_progress(self, progress_id: str) -> None:
        """清理过期进度记录。"""
        with self._refresh_progress_lock:
            self._refresh_progress.pop(progress_id, None)

    # ---- 重新登录进度追踪 ----

    def init_relogin_progress(self, progress_id: str, total: int) -> None:
        """初始化重新登录进度记录。"""
        with self._relogin_progress_lock:
            self._relogin_progress[progress_id] = {
                "total": total,
                "processed": 0,
                "done": False,
                "error": None,
                "results": [],
            }

    def update_relogin_progress(
        self,
        progress_id: str,
        token: str,
        status: str,
        error: str | None = None,
        extra: dict | None = None,
    ) -> None:
        """更新单个重新登录进度。当所有账号处理完毕时自动标记完成。"""
        with self._relogin_progress_lock:
            progress = self._relogin_progress.get(progress_id)
            if progress is None:
                return
            progress["processed"] += 1
            item = {
                "token": anonymize_token(token),
                "status": status,
                "error": error,
            }
            if isinstance(extra, dict):
                for key, value in extra.items():
                    if key in {"token", "status", "error"}:
                        continue
                    item[key] = value
            progress["results"].append(item)
            if progress["processed"] >= progress["total"]:
                progress["done"] = True

    def finish_relogin_progress(self, progress_id: str, result: dict | None = None, error: str | None = None) -> None:
        """标记重新登录完成。"""
        with self._relogin_progress_lock:
            progress = self._relogin_progress.get(progress_id)
            if progress is None:
                return
            progress["done"] = True
            progress["result"] = result
            if error:
                progress["error"] = error

    def get_relogin_progress(self, progress_id: str) -> dict | None:
        """查询重新登录进度。"""
        with self._relogin_progress_lock:
            progress = self._relogin_progress.get(progress_id)
            return dict(progress) if progress else None

    def clean_relogin_progress(self, progress_id: str) -> None:
        """清理过期进度记录。"""
        with self._relogin_progress_lock:
            self._relogin_progress.pop(progress_id, None)

    def refresh_accounts(
        self,
        access_tokens: list[str],
        progress_id: str | None = None,
        defer_invalid_removal: bool = True,
    ) -> dict[str, Any]:
        access_tokens = list(dict.fromkeys(token for token in access_tokens if token))
        if not access_tokens:
            items = self.list_accounts()
            result = {"refreshed": 0, "errors": [], "items": items, "relogined": 0}
            if progress_id:
                self.finish_refresh_progress(progress_id, result)
            return result

        refreshed = 0
        errors = []
        max_workers = min(10, len(access_tokens))

        if progress_id:
            self.init_refresh_progress(progress_id, len(access_tokens))

        executor = ThreadPoolExecutor(max_workers=max_workers)
        try:
            futures = {
                executor.submit(self.fetch_remote_info, token, "refresh_accounts", defer_invalid_removal): token
                for token in access_tokens
            }
            for future in as_completed(futures):
                token = futures[future]
                try:
                    account = future.result()
                except (KeyboardInterrupt, SystemExit):
                    executor.shutdown(wait=False, cancel_futures=True)
                    raise
                except Exception as exc:
                    error_str = str(exc)
                    # TLS/代理连接错误是网络问题，不计入账号失败
                    from services.protocol.conversation import is_tls_connection_error
                    if not is_tls_connection_error(error_str):
                        errors.append({"token": anonymize_token(token), "error": error_str})
                else:
                    if account is not None:
                        refreshed += 1

                if progress_id:
                    self.update_refresh_progress(progress_id, token)
        except (KeyboardInterrupt, SystemExit):
            if progress_id:
                self.finish_refresh_progress(progress_id, error="cancelled")
            executor.shutdown(wait=False, cancel_futures=True)
            raise
        else:
            executor.shutdown(wait=True, cancel_futures=True)

        # 自动重新登录异常账号（仅当配置开启时）
        relogined = 0
        if config.auto_relogin_after_refresh:
            for token in access_tokens:
                account = self.get_account(token)
                if not account:
                    continue
                status = str(account.get("status") or "").strip()
                if status != "异常":
                    continue
                email = str(account.get("email") or "").strip()
                password = str(account.get("password") or "").strip()
                if not email:
                    continue
                if self._schedule_relogin_fallback(
                    token,
                    "auto_relogin_after_refresh",
                    reason="status_abnormal",
                ):
                    relogined += 1

        result = {
            "refreshed": refreshed,
            "errors": errors,
            "items": self.list_accounts(),
            "relogined": relogined,
        }

        if progress_id:
            self.finish_refresh_progress(progress_id, result)

        return result

    def re_login_accounts(self, access_tokens: list[str], progress_id: str | None = None) -> dict[str, Any]:
        self._relogin_trace(
            "batch_start",
            count=len(access_tokens or []),
            progress_id=progress_id or "",
        )
        """对选中账号执行重新登录流程。

        - email + password: 密码登录（必要时邮箱 OTP 二次验证）
        - 仅 email: passwordless 邮箱验证码登录
        登录成功后自动将状态设为"正常"。
        """
        access_tokens = list(dict.fromkeys(token for token in access_tokens if token))
        if not access_tokens:
            result = {"relogined": 0, "skipped": 0, "errors": [], "items": self.list_accounts()}
            if progress_id:
                self.finish_relogin_progress(progress_id, result)
            return result

        if progress_id:
            self.init_relogin_progress(progress_id, len(access_tokens))

        relogined = 0
        skipped = 0
        errors = []

        for token in access_tokens:
            account = self.get_account(token)
            if not account:
                errors.append({"token": anonymize_token(token), "error": "账号不存在"})
                if progress_id:
                    self.update_relogin_progress(progress_id, token, "跳过", "账号不存在")
                continue

            email = str(account.get("email") or "").strip()
            password = str(account.get("password") or "").strip()
            if not email:
                skipped += 1
                if progress_id:
                    self.update_relogin_progress(progress_id, token, "跳过", "无邮箱")
                continue

            # 有密码走密码登录，仅邮箱走验证码登录
            self._relogin_trace(
                "thread_spawn",
                email=email,
                method="password" if password else "email_otp",
                token=anonymize_token(token),
                mail_inbox=str(account.get("mail_inbox") or ""),
                mail_provider_ref=str(account.get("mail_provider_ref") or ""),
                mail_provider_type=str(account.get("mail_provider_type") or ""),
            )
            if self._schedule_relogin_fallback(
                token,
                "manual_relogin",
                reason="manual",
                progress_id=progress_id,
            ):
                relogined += 1

        result = {
            "relogined": relogined,
            "skipped": skipped,
            "errors": errors,
            "items": self.list_accounts(),
        }
        if progress_id:
            # 如果所有账号都已同步处理完毕（没有启动线程），直接标记完成
            if relogined == 0:
                self.finish_relogin_progress(progress_id, result)
            else:
                # 有线程在运行，等线程结束后再完成
                pass
        return result

    def build_export_items(self, access_tokens: list[str] | None = None) -> list[dict[str, str]]:
        target_tokens = set(token for token in (access_tokens or []) if token)
        with self._lock:
            accounts = [
                dict(item)
                for item in self._accounts.values()
                if not target_tokens or str(item.get("access_token") or "") in target_tokens
            ]

        items: list[dict[str, str]] = []
        for account in accounts:
            access_token = str(account.get("access_token") or "").strip()
            refresh_token = str(account.get("refresh_token") or "").strip()
            id_token = str(account.get("id_token") or "").strip()
            if not access_token or not refresh_token or not id_token:
                continue

            access_payload = self._decode_jwt_payload(access_token)
            id_payload = self._decode_jwt_payload(id_token)
            auth_claim = access_payload.get("https://api.openai.com/auth")
            auth_claim = auth_claim if isinstance(auth_claim, dict) else {}
            profile_claim = access_payload.get("https://api.openai.com/profile")
            profile_claim = profile_claim if isinstance(profile_claim, dict) else {}

            email = (
                str(account.get("email") or "").strip()
                or str(profile_claim.get("email") or "").strip()
                or str(id_payload.get("email") or "").strip()
            )
            account_id = (
                str(account.get("account_id") or "").strip()
                or str(auth_claim.get("chatgpt_account_id") or "").strip()
                or str(account.get("user_id") or "").strip()
            )
            item = {
                "type": str(account.get("export_type") or "codex"),
                "email": email,
                "account_id": account_id,
                "access_token": access_token,
                "refresh_token": refresh_token,
                "id_token": id_token,
                "expired": self._timestamp_to_iso(access_payload.get("exp")),
                "last_refresh": self._timestamp_to_iso(access_payload.get("iat")),
            }
            password = str(account.get("password") or "").strip()
            if password:
                item["password"] = password
            items.append(item)
        return items

    def get_stats(self) -> dict:
        with self._lock:
            items = list(self._accounts.values())
        total = len(items)
        active = sum(1 for a in items if a.get("status") == "正常")
        limited = sum(1 for a in items if a.get("status") == "限流")
        abnormal = sum(1 for a in items if a.get("status") == "异常")
        disabled = sum(1 for a in items if a.get("status") == "禁用")
        total_quota = sum(max(0, int(a.get("quota") or 0)) for a in items if a.get("status") == "正常")
        total_success = sum(int(a.get("success") or 0) for a in items)
        total_fail = sum(int(a.get("fail") or 0) for a in items)
        by_type = {}
        for a in items:
            t = a.get("type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1
        return {
            "total": total,
            "cumulative_total": self._cumulative_total,
            "active": active,
            "limited": limited,
            "abnormal": abnormal,
            "disabled": disabled,
            "total_quota": total_quota,
            "total_success": total_success,
            "total_fail": total_fail,
            "by_type": by_type,
        }

    def account_health(self) -> dict:
        stats = self.get_stats()
        return {
            "healthy": stats["active"] > 0,
            "status": "ok" if stats["active"] > 0 else "degraded",
            **stats,
        }


account_service = AccountService(config.get_storage_backend())
