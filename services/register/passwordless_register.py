# -*- coding: utf-8 -*-
"""Passwordless ChatGPT signup flow aligned with 2026-08 official HAR.

This is an additive path. Legacy password register in openai_register.PlatformRegistrar
is left intact and remains the default.
"""

from __future__ import annotations

import json
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from services.register import mail_provider
from services.register.chatgpt_web_entry import ChatGPTWebEntry
from services.register.openai_register import (
    PlatformRegistrar,
    _headers_with_clearance,
    _is_cloudflare_challenge,
    _cloudflare_block_message,
    _random_birthdate,
    _random_name,
    _random_password,
    _response_debug_detail,
    _response_json,
    auth_base,
    chatgpt_base,
    create_mailbox,
    default_timeout,
    extract_oauth_callback_params_from_url,
    request_with_local_retry,
    step,
    wait_for_code,
)
from utils.sentinel import build_sentinel_token_bundle


def _apply_oai_sc(session: Any, oai_sc: str) -> None:
    value = str(oai_sc or "").strip()
    if not value:
        return
    for domain in (".openai.com", "auth.openai.com", ".auth.openai.com", "sentinel.openai.com", ".sentinel.openai.com"):
        try:
            session.cookies.set("oai-sc", value, domain=domain)
        except Exception:
            continue


def _apply_set_cookies(session: Any, set_cookies: list[str] | None) -> str:
    """Apply Set-Cookie lines from sentinel/req; return oai-sc if present."""
    oai_sc = ""
    for raw in set_cookies or []:
        line = str(raw or "").strip()
        if not line or "=" not in line:
            continue
        first = line.split(";", 1)[0].strip()
        name, _, value = first.partition("=")
        name = name.strip()
        value = value.strip()
        if not name or not value:
            continue
        if name.lower() == "oai-sc":
            oai_sc = value
        for domain in (".openai.com", "auth.openai.com", ".auth.openai.com", "sentinel.openai.com", ".sentinel.openai.com"):
            try:
                session.cookies.set(name, value, domain=domain)
            except Exception:
                continue
    if oai_sc:
        _apply_oai_sc(session, oai_sc)
    return oai_sc


class PasswordlessRegistrar(PlatformRegistrar):
    """Official-like passwordless signup:

    chatgpt web entry (login_or_signup)
      -> email OTP validate (flow=email_otp_validate + SO token)
      -> create_account (flow=oauth_create_account + SO token)
      -> chatgpt session exchange
    """

    FLOW_NAME = "passwordless"

    def _build_flow_headers(
        self,
        referer: str,
        flow: str,
        *,
        page_url: str = "",
        require_real_t: bool = True,
        with_so: bool = True,
    ) -> dict[str, str]:
        headers = self._json_headers(referer)
        headers["accept"] = "application/json"
        headers["origin"] = auth_base
        headers["oai-device-id"] = self.device_id
        # Match official auth web request correlation headers (best-effort).
        headers["x-access-flow-invocation-id"] = str(uuid.uuid4())
        if not getattr(self, "document_navigation_id", None):
            self.document_navigation_id = str(uuid.uuid4())
        headers["x-openai-document-navigation-id"] = str(self.document_navigation_id)

        bundle = build_sentinel_token_bundle(
            self.session,
            self.device_id,
            flow,
            user_agent=self.clearance_user_agent or "",
            page_url=page_url or referer,
            prefer_node=True if require_real_t else None,
            with_so=with_so,
            require_real_t=require_real_t,
        )
        token = str(bundle.get("token") or "").strip()
        if not token:
            raise RuntimeError(f"sentinel_token_empty_flow_{flow}")
        headers["openai-sentinel-token"] = token

        so_token = str(bundle.get("so_token") or "").strip()
        if with_so:
            if not so_token:
                raise RuntimeError(f"sentinel_so_token_empty_flow_{flow}")
            headers["openai-sentinel-so-token"] = so_token

        oai_sc = str(bundle.get("oai_sc") or "").strip()
        if oai_sc:
            _apply_oai_sc(self.session, oai_sc)
        _apply_set_cookies(self.session, bundle.get("set_cookies") if isinstance(bundle.get("set_cookies"), list) else [])
        return headers

    def _authorize_bootstrap(self, email: str, index: int) -> None:
        """ChatGPT website entry with official login_or_signup + ccaps."""

        def _log(msg: str) -> None:
            if any(k in msg for k in ("官网入口完成", "失败", "CF", "Cloudflare")):
                step(index, msg)

        entry = ChatGPTWebEntry(
            email,
            proxy=self.proxy,
            log=_log,
            timeout=default_timeout,
            verbose=False,
            screen_hint="login_or_signup",
            extra_query={"ccaps": "login_methods"},
        )
        try:
            result = entry.execute()
        except Exception as exc:
            entry.close()
            raise RuntimeError(f"ChatGPT 官网入口异常: {exc}") from exc

        if not result.success:
            try:
                entry.close()
            except Exception:
                pass
            err = result.error or "unknown"
            raise RuntimeError(
                f"ChatGPT 官网入口失败: {err}。"
                "passwordless 流程依赖 chatgpt.com -> authorize 纯协议入口。"
            )

        try:
            self.session.close()
        except Exception:
            pass
        self.session = result.session
        self.entry_mode = "chatgpt_web_passwordless"
        if result.device_id:
            self.device_id = result.device_id
        profile = result.profile or {}
        if profile.get("user_agent"):
            self.clearance_user_agent = str(profile["user_agent"])
            try:
                self.session.headers["User-Agent"] = self.clearance_user_agent
                self.session.headers["user-agent"] = self.clearance_user_agent
            except Exception:
                pass
        self.code_verifier = ""
        self.document_navigation_id = str(uuid.uuid4())
        self.entry_page_type = str(result.page_type or "").strip()
        self.entry_final_url = str(result.final_url or "").strip()
        step(
            index,
            f"官网入口完成[passwordless/{self.entry_page_type or '?'}] url={self.entry_final_url[:160]}",
        )

    def _maybe_send_otp(self, index: int) -> None:
        page = str(getattr(self, "entry_page_type", "") or "").lower()
        final_url = str(getattr(self, "entry_final_url", "") or "").lower()
        already_on_otp = (
            "email" in page and ("otp" in page or "verification" in page)
        ) or ("email-verification" in final_url)
        if already_on_otp:
            step(index, "入口已在邮箱验证页，跳过主动发码")
            return

        step(index, "开始触发 passwordless 验证码")
        # Official HAR often auto-sends OTP during authorize. If we landed elsewhere,
        # try passwordless/send-otp first, then legacy email-otp/send.
        candidates = [
            (
                "passwordless/send-otp",
                "post",
                f"{auth_base}/api/accounts/passwordless/send-otp",
                f"{auth_base}/log-in/password",
            ),
            (
                "email-otp/send",
                "get",
                f"{auth_base}/api/accounts/email-otp/send",
                f"{auth_base}/email-verification",
            ),
        ]
        last_error = ""
        for name, method, url, referer in candidates:
            headers = _headers_with_clearance(
                self._navigate_headers(referer) if method == "get" else self._json_headers(referer),
                url,
                self.proxy,
                self.clearance_user_agent,
            )
            if method == "post":
                headers["content-type"] = "application/json"
                resp, error = request_with_local_retry(
                    self.session,
                    "post",
                    url,
                    json={},
                    headers=headers,
                    verify=False,
                )
            else:
                resp, error = request_with_local_retry(
                    self.session,
                    "get",
                    url,
                    headers=headers,
                    allow_redirects=True,
                    verify=False,
                )
            if resp is not None and int(getattr(resp, "status_code", 0) or 0) in (200, 201, 202, 204, 302):
                step(index, f"触发验证码完成[{name}]")
                return
            detail = _response_debug_detail(resp) if resp is not None else error
            last_error = f"{name}: {detail or error or 'unknown'}"
            step(index, f"触发验证码失败[{name}]，尝试下一个通道", "yellow")
        raise RuntimeError(f"passwordless_send_otp_failed: {last_error}")

    def _validate_otp(self, code: str, index: int) -> None:
        step(index, f"开始校验验证码 {code}")
        url = f"{auth_base}/api/accounts/email-otp/validate"
        referer = f"{auth_base}/email-verification"
        headers = self._build_flow_headers(
            referer,
            "email_otp_validate",
            page_url=referer,
            require_real_t=True,
            with_so=True,
        )
        headers = _headers_with_clearance(headers, url, self.proxy, self.clearance_user_agent)
        resp, error = request_with_local_retry(
            self.session,
            "post",
            url,
            json={"code": str(code or "").strip()},
            headers=headers,
            verify=False,
        )
        if _is_cloudflare_challenge(resp):
            bundle = self._refresh_cloudflare_clearance(auth_base, index)
            if bundle is None:
                raise RuntimeError(_cloudflare_block_message(resp, reason=self.clearance_failure_reason))
            headers = self._build_flow_headers(
                referer,
                "email_otp_validate",
                page_url=referer,
                require_real_t=True,
                with_so=True,
            )
            headers = _headers_with_clearance(headers, url, self.proxy, self.clearance_user_agent)
            resp, error = request_with_local_retry(
                self.session,
                "post",
                url,
                json={"code": str(code or "").strip()},
                headers=headers,
                verify=False,
            )
            if _is_cloudflare_challenge(resp):
                raise RuntimeError(_cloudflare_block_message(resp, "Cloudflare clearance 重试仍被拦截"))

        if resp is None or int(getattr(resp, "status_code", 0) or 0) != 200:
            data = _response_json(resp) if resp is not None else {}
            detail = f", detail={json.dumps(data, ensure_ascii=False)}" if data else f", {error or _response_debug_detail(resp)}"
            raise RuntimeError(f"validate_otp_http_{getattr(resp, 'status_code', 'unknown')}{detail}")

        data = _response_json(resp)
        continue_url = str(data.get("continue_url") or "").strip()
        page = data.get("page") if isinstance(data.get("page"), dict) else {}
        page_type = str((page or {}).get("type") or "").strip()
        if continue_url:
            step(index, f"验证码校验完成 -> {continue_url[:120]} [{page_type or '?'}]")
        else:
            step(index, f"验证码校验完成 [{page_type or '?'}]")
        if page_type and page_type not in {"about_you"} and "about-you" not in continue_url:
            # Still allow create_account attempt; official success continues to about-you.
            step(index, f"OTP 后页面非 about-you: {page_type or continue_url or '?'}", "yellow")

    def _create_account(self, name: str, birthdate: str, index: int) -> None:
        step(index, "开始填写账号资料[passwordless]")
        url = f"{auth_base}/api/accounts/create_account"
        referer = f"{auth_base}/about-you"
        headers = self._build_flow_headers(
            referer,
            "oauth_create_account",
            page_url=referer,
            require_real_t=True,
            with_so=True,
        )
        headers = _headers_with_clearance(headers, url, self.proxy, self.clearance_user_agent)
        payload = {"name": name, "birthdate": birthdate}
        resp, error = request_with_local_retry(
            self.session,
            "post",
            url,
            json=payload,
            headers=headers,
            verify=False,
        )
        if _is_cloudflare_challenge(resp):
            bundle = self._refresh_cloudflare_clearance(auth_base, index)
            if bundle is None:
                raise RuntimeError(_cloudflare_block_message(resp, reason=self.clearance_failure_reason))
            headers = self._build_flow_headers(
                referer,
                "oauth_create_account",
                page_url=referer,
                require_real_t=True,
                with_so=True,
            )
            headers = _headers_with_clearance(headers, url, self.proxy, self.clearance_user_agent)
            resp, error = request_with_local_retry(
                self.session,
                "post",
                url,
                json=payload,
                headers=headers,
                verify=False,
            )
            if _is_cloudflare_challenge(resp):
                raise RuntimeError(_cloudflare_block_message(resp, "Cloudflare clearance 重试仍被拦截"))

        if resp is None or int(getattr(resp, "status_code", 0) or 0) not in (200, 302):
            data = _response_json(resp) if resp is not None else {}
            code = ""
            if isinstance(data.get("error"), dict):
                code = str(data["error"].get("code") or "")
            if code == "registration_disallowed" or "registration_disallowed" in json.dumps(data, ensure_ascii=False):
                step(index, "create_account 被拒绝: registration_disallowed（会话/风控/SO token 仍可能不足）", "yellow")
            detail = f", detail={json.dumps(data, ensure_ascii=False)}" if data else f", {error or ''}"
            raise RuntimeError(error or f"create_account_http_{getattr(resp, 'status_code', 'unknown')}{detail}")

        data = _response_json(resp)
        self.continue_url = str(data.get("continue_url") or "").strip()
        if not self.continue_url:
            page = data.get("page") if isinstance(data.get("page"), dict) else {}
            payload_obj = page.get("payload") if isinstance(page, dict) and isinstance(page.get("payload"), dict) else {}
            self.continue_url = str((payload_obj or {}).get("url") or "").strip()
        callback_params = extract_oauth_callback_params_from_url(self.continue_url)
        self.platform_auth_code = str((callback_params or {}).get("code") or "").strip()
        step(index, "填写账号资料完成[passwordless]")

    def register(self, index: int) -> dict:
        step(index, "开始创建邮箱[passwordless]")
        mailbox = create_mailbox(register_proxy=self.proxy)
        email = str(mailbox.get("address") or "").strip()
        if not email:
            mail_provider.release_mailbox(mailbox)
            raise RuntimeError("邮箱服务未返回 address")
        label = str(mailbox.get("label") or "")
        step(index, f"邮箱创建完成[{label}]: {email}")
        try:
            # Keep a password field for account storage compatibility; official path is passwordless.
            password = _random_password()
            first_name, last_name = _random_name()
            self._authorize_bootstrap(email, index)
            self._maybe_send_otp(index)
            step(index, "开始等待注册验证码[passwordless]")
            code = wait_for_code(mailbox, register_proxy=self.proxy)
            if not code:
                raise RuntimeError("等待注册验证码超时")
            step(index, f"收到注册验证码: {code}")
            self._validate_otp(code, index)
            self._create_account(f"{first_name} {last_name}", _random_birthdate(), index)
            tokens = self._exchange_registered_tokens(index)
        except Exception as error:
            mail_provider.mark_mailbox_result(mailbox, success=False, error=error)
            raise
        mail_provider.mark_mailbox_result(mailbox, success=True)
        return {
            "email": str(tokens.get("email") or email).strip(),
            "password": password,
            "access_token": str(tokens.get("access_token") or "").strip(),
            "refresh_token": str(tokens.get("refresh_token") or "").strip(),
            "id_token": str(tokens.get("id_token") or "").strip(),
            "session_token": str(tokens.get("session_token") or "").strip(),
            "account_id": str(tokens.get("account_id") or "").strip(),
            "source_type": str(tokens.get("source") or tokens.get("source_type") or "chatgpt_session"),
            "register_flow": self.FLOW_NAME,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
