# -*- coding: utf-8 -*-
"""Platform OAuth signup aligned with 2026-09 platform.openai.com HAR.

Flow:
  GET /api/accounts/authorize (platform client + PKCE, no login_hint)
  POST /api/accounts/authorize/continue (email + screen_hint=signup, sentinel only)
  auto OTP (no user/register, no email-otp/send)
  POST /api/accounts/email-otp/validate (sentinel + SO token)
  POST /api/accounts/create_account (sentinel + SO token)
  POST /api/accounts/oauth/token (authorization_code + code_verifier) → AT/RT
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

from services.register import mail_provider
from services.register.chatgpt_web_entry import fetch_chatgpt_web_session
from services.register.openai_register import (
    _cloudflare_block_message,
    _headers_with_clearance,
    _is_cloudflare_challenge,
    _random_birthdate,
    _random_name,
    _random_password,
    _response_debug_detail,
    _response_json,
    auth_base,
    create_mailbox,
    extract_oauth_callback_params_from_url,
    platform_base,
    request_platform_oauth_token,
    request_with_local_retry,
    step,
    user_agent,
    wait_for_code,
)
from services.register.passwordless_register import PasswordlessRegistrar

_CODE_RE = re.compile(r"[?&]code=([A-Za-z0-9._\-]+)")


class PlatformHarRegistrar(PasswordlessRegistrar):
    FLOW_NAME = "platform"

    def _json_headers(self, referer: str) -> dict[str, str]:
        headers = super()._json_headers(referer)
        headers.pop("oai-device-id", None)
        headers.pop("dnt", None)
        headers.pop("sec-gpc", None)
        for key in list(headers):
            if key.startswith("trace") or key.startswith("x-datadog"):
                headers.pop(key, None)
        return headers

    def _visit_auth_page(self, path: str, referer: str, index: int) -> None:
        url = path if str(path).startswith("http") else f"{auth_base}{path}"
        headers = self._navigate_headers(referer)
        headers = _headers_with_clearance(headers, url, self.proxy, self.clearance_user_agent)
        resp, error = request_with_local_retry(
            self.session,
            "get",
            url,
            headers=headers,
            allow_redirects=True,
            verify=False,
        )
        status = getattr(resp, "status_code", None) if resp is not None else None
        final = str(getattr(resp, "url", "") or url)[:160] if resp is not None else url
        if resp is None or int(status or 0) >= 400:
            step(index, f"打开 {urlparse(url).path or url} 失败 status={status} {error or ''}", "yellow")
            return
        step(index, f"打开页面 {urlparse(final).path or urlparse(url).path} HTTP {status}")

    def _authorize_continue_email(self, email: str, index: int) -> None:
        step(index, "开始提交邮箱[platform continue]")
        if not getattr(self, "document_navigation_id", None):
            self.document_navigation_id = str(uuid.uuid4())
        url = f"{auth_base}/api/accounts/authorize/continue"
        referer = f"{auth_base}/create-account"
        headers = self._build_flow_headers(
            referer,
            "authorize_continue",
            page_url=referer,
            require_real_t=True,
            with_so=False,
        )
        headers = _headers_with_clearance(headers, url, self.proxy, self.clearance_user_agent)
        payload = {
            "username": {"kind": "email", "value": email},
            "screen_hint": "signup",
        }
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
                "authorize_continue",
                page_url=referer,
                require_real_t=True,
                with_so=False,
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
        if resp is None or int(getattr(resp, "status_code", 0) or 0) != 200:
            data = _response_json(resp) if resp is not None else {}
            detail = f", detail={json.dumps(data, ensure_ascii=False)}" if data else f", {error or _response_debug_detail(resp)}"
            raise RuntimeError(f"authorize_continue_http_{getattr(resp, 'status_code', 'unknown')}{detail}")
        data = _response_json(resp)
        page = data.get("page") if isinstance(data.get("page"), dict) else {}
        page_type = str((page or {}).get("type") or "").strip()
        continue_url = str(data.get("continue_url") or "").strip()
        step(index, f"提交邮箱完成[platform] page={page_type or '?'} url={(continue_url or '')[:120]}")
        self._visit_auth_page("/email-verification", f"{auth_base}/create-account", index)

    def _take_oauth_code(self, raw: str) -> bool:
        text = str(raw or "").strip()
        if not text:
            return False
        params = extract_oauth_callback_params_from_url(text)
        code = str((params or {}).get("code") or "").strip()
        if not code:
            match = _CODE_RE.search(text)
            code = str(match.group(1) if match else "").strip()
        if not code:
            return False
        self.continue_url = text if text.startswith("http") else self.continue_url
        self.platform_auth_code = code
        return True

    def _collect_redirect_candidates(self, resp, data: dict) -> list[str]:
        out: list[str] = []
        if resp is not None:
            headers = getattr(resp, "headers", {}) or {}
            for key in ("Location", "location"):
                try:
                    value = str(headers.get(key) or "").strip()
                except Exception:
                    value = ""
                if value:
                    out.append(value)
            final_url = str(getattr(resp, "url", "") or "").strip()
            if final_url:
                out.append(final_url)
            for hist in getattr(resp, "history", None) or []:
                hist_url = str(getattr(hist, "url", "") or "").strip()
                if hist_url:
                    out.append(hist_url)
        if isinstance(data, dict):
            out.append(str(data.get("continue_url") or ""))
            page = data.get("page") if isinstance(data.get("page"), dict) else {}
            payload = page.get("payload") if isinstance(page.get("payload"), dict) else {}
            if isinstance(payload, dict):
                for key in ("url", "redirect_url", "continue_url", "redirect"):
                    out.append(str(payload.get(key) or ""))
            for key in ("url", "redirect_url", "redirect"):
                out.append(str(data.get(key) or ""))
        seen: set[str] = set()
        uniq: list[str] = []
        for item in out:
            value = str(item or "").strip()
            if not value or value in seen:
                continue
            seen.add(value)
            uniq.append(value)
        return uniq

    def _follow_continue_for_code(self, index: int) -> None:
        raw = str(self.continue_url or "").strip()
        if not raw:
            return
        url = raw if raw.startswith("http") else urljoin(auth_base + "/", raw.lstrip("/"))
        if url.startswith("/"):
            url = urljoin(platform_base + "/", url.lstrip("/"))
        headers = self._navigate_headers(f"{auth_base}/about-you")
        headers = _headers_with_clearance(headers, url, self.proxy, self.clearance_user_agent)
        resp, error = request_with_local_retry(
            self.session,
            "get",
            url,
            headers=headers,
            allow_redirects=True,
            verify=False,
        )
        if resp is None:
            step(index, f"跟随 continue_url 失败: {error or 'no response'}", "yellow")
            return
        data = _response_json(resp)
        for candidate in self._collect_redirect_candidates(resp, data):
            if self._take_oauth_code(candidate):
                step(index, f"跟随 continue_url 拿到 platform code url={candidate[:160]}")
                return
        raw_text = ""
        try:
            raw_text = str(getattr(resp, "text", "") or "")
        except Exception:
            raw_text = ""
        if self._take_oauth_code(raw_text):
            step(index, "从 continue 响应正文解析到 platform code")

    def _create_account(self, name: str, birthdate: str, index: int) -> None:
        super()._create_account(name, birthdate, index)
        if not str(self.platform_auth_code or "").strip():
            self._follow_continue_for_code(index)
        step(
            index,
            "platform 换票材料 "
            f"code={'yes' if self.platform_auth_code else 'no'} "
            f"verifier={len(str(self.code_verifier or ''))} "
            f"continue={(self.continue_url or '')[:180]}",
        )

    def _exchange_platform_oauth(self, index: int) -> dict:
        step(index, "开始换 token[platform oauth]")
        if not str(self.code_verifier or "").strip():
            raise RuntimeError("platform oauth 缺少 code_verifier（authorize PKCE 丢失）")
        if not str(self.platform_auth_code or "").strip():
            raise RuntimeError(
                "platform oauth 缺少 authorization code "
                f"continue={(self.continue_url or '')[:240]!r}"
            )
        tokens = request_platform_oauth_token(self.session, self.platform_auth_code, self.code_verifier)
        if not tokens or not str(tokens.get("access_token") or "").strip():
            raise RuntimeError("platform oauth/token 换取失败")
        has_rt = bool(str(tokens.get("refresh_token") or "").strip())
        step(index, f"token 换取完成[platform] rt={'yes' if has_rt else 'no'}")
        return {
            "access_token": str(tokens.get("access_token") or "").strip(),
            "refresh_token": str(tokens.get("refresh_token") or "").strip(),
            "id_token": str(tokens.get("id_token") or "").strip(),
            "session_token": "",
            "account_id": "",
            "email": str(tokens.get("email") or "").strip(),
            "source": "platform_oauth",
            "expires_in": tokens.get("expires_in"),
        }

    def _merge_chatgpt_web_session(self, index: int, tokens: dict) -> dict:
        """create_account 会种 unified_session cookie；HAR 随后 GET platform callback。
        再读 chatgpt.com/api/auth/session，尽量拿到网页 AT 供巡检/生图。"""
        callback = str(self.continue_url or "").strip()
        if not callback and self.platform_auth_code:
            callback = f"{platform_base}/auth/callback?code={self.platform_auth_code}"
        try:
            web = fetch_chatgpt_web_session(
                self.session,
                continue_url=callback,
                user_agent=self.clearance_user_agent or user_agent,
            )
        except Exception as exc:
            step(index, f"chatgpt session 交换失败: {exc}", "yellow")
            return tokens
        if not web.get("ok") and not web.get("access_token"):
            step(index, f"chatgpt session 未返回 AT: {str(web.get('error') or '')[:160]}", "yellow")
            return tokens
        web_at = str(web.get("access_token") or "").strip()
        if not web_at:
            return tokens
        merged = dict(tokens)
        merged["access_token"] = web_at
        merged["session_token"] = str(web.get("session_token") or "").strip()
        merged["account_id"] = str(web.get("account_id") or merged.get("account_id") or "").strip()
        if web.get("email"):
            merged["email"] = str(web.get("email") or "").strip()
        if not merged.get("id_token") and web.get("id_token"):
            merged["id_token"] = str(web.get("id_token") or "").strip()
        merged["source"] = "chatgpt_session"
        step(index, "已附加 chatgpt.com session AT（保留 platform RT）")
        return merged

    def register(self, index: int) -> dict:
        step(index, "开始创建邮箱[platform]")
        mailbox = create_mailbox(register_proxy=self.proxy)
        email = str(mailbox.get("address") or "").strip()
        if not email:
            mail_provider.release_mailbox(mailbox)
            raise RuntimeError("邮箱服务未返回 address")
        label = str(mailbox.get("label") or "")
        step(index, f"邮箱创建完成[{label}]: {email}")
        try:
            password = _random_password()
            first_name, last_name = _random_name()
            self.document_navigation_id = str(uuid.uuid4())
            self._platform_authorize(email, index, login_hint=False)
            self._authorize_continue_email(email, index)
            step(index, "开始等待注册验证码[platform]")
            code = wait_for_code(mailbox, register_proxy=self.proxy)
            if not code:
                raise RuntimeError("等待注册验证码超时")
            step(index, f"收到注册验证码: {code}")
            self._validate_otp(code, index)
            self._visit_auth_page("/about-you", f"{auth_base}/email-verification", index)
            self._create_account(f"{first_name} {last_name}", _random_birthdate(), index)
            tokens = self._exchange_platform_oauth(index)
            tokens = self._merge_chatgpt_web_session(index, tokens)
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
            "source_type": str(tokens.get("source") or "platform_oauth"),
            "register_flow": self.FLOW_NAME,
            "mail_provider_ref": str(mailbox.get("provider_ref") or ""),
            "mail_provider_type": str(mailbox.get("provider") or "icloud"),
            "mail_inbox": str(mailbox.get("inbox_address") or mailbox.get("mail_inbox") or ""),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
