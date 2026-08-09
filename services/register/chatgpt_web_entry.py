# -*- coding: utf-8 -*-
"""Pure-protocol ChatGPT website OAuth entry (no browser).

Aligned with codex-console chatgpt_entry_flow + freeAgentIdentity protocol_register.
"""

from __future__ import annotations

import json
import random
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlencode, urlparse

from curl_cffi import requests

CHATGPT_BASE = "https://chatgpt.com"
AUTH_BASE = "https://auth.openai.com"

_CHROME_PROFILES = (
    {
        "major": 131,
        "impersonate": "chrome131",
        "build": 6778,
        "patch_range": (69, 205),
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    },
    {
        "major": 124,
        "impersonate": "chrome124",
        "build": 6367,
        "patch_range": (60, 243),
        "sec_ch_ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    },
    {
        "major": 120,
        "impersonate": "chrome120",
        "build": 6099,
        "patch_range": (62, 224),
        "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
    },
)


def _pick_profile() -> dict[str, Any]:
    base = random.choice(_CHROME_PROFILES)
    major = int(base["major"])
    build = int(base["build"])
    lo, hi = base["patch_range"]
    patch = random.randint(int(lo), int(hi))
    full = f"{major}.0.{build}.{patch}"
    ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        f"Chrome/{full} Safari/537.36"
    )
    return {
        "impersonate": str(base["impersonate"]),
        "user_agent": ua,
        "sec_ch_ua": str(base["sec_ch_ua"]),
        "sec_ch_ua_full_version": f'"{full}"',
        "sec_ch_ua_full_version_list": (
            f'"Chromium";v="{full}", "Google Chrome";v="{full}", '
            '"Not.A/Brand";v="99.0.0.0"'
        ),
        "chrome_full": full,
    }


def _is_cf_challenge(resp: Any) -> bool:
    if resp is None:
        return False
    try:
        status = int(getattr(resp, "status_code", 0) or 0)
    except Exception:
        status = 0
    try:
        headers = {
            str(k).lower(): str(v)
            for k, v in dict(getattr(resp, "headers", {}) or {}).items()
        }
    except Exception:
        headers = {}
    try:
        text = str(getattr(resp, "text", "") or "")[:4000]
    except Exception:
        text = ""
    if status in (403, 503):
        if "challenge" in headers.get("cf-mitigated", "").lower():
            return True
        if headers.get("cf-ray"):
            return True
        if any(
            m in text
            for m in (
                "Just a moment",
                "_cf_chl_opt",
                "challenge-platform",
                "cf-browser-verification",
                "Attention Required",
            )
        ):
            return True
        if "cloudflare" in headers.get("server", "").lower():
            return True
    if status == 200 and ("Just a moment" in text or "_cf_chl_opt" in text):
        return True
    return False


@dataclass
class ChatGPTWebEntryResult:
    success: bool = False
    error: str = ""
    device_id: str = ""
    authorize_url: str = ""
    final_url: str = ""
    page_type: str = ""
    session: Any = None
    profile: dict[str, Any] = field(default_factory=dict)




def _cookie_from_session(session: Any, name: str, *domains: str) -> str:
    for domain in domains:
        try:
            val = session.cookies.get(name, domain=domain)
            if val:
                return str(val)
        except Exception:
            continue
    try:
        val = session.cookies.get(name)
        if val:
            return str(val)
    except Exception:
        pass
    # jar fallback
    try:
        jar = getattr(session.cookies, "jar", None)
        if jar is not None:
            for c in list(jar):
                if str(getattr(c, "name", "") or "") == name and str(getattr(c, "value", "") or ""):
                    return str(c.value)
    except Exception:
        pass
    return ""


def fetch_chatgpt_web_session(
    session: Any,
    *,
    continue_url: str = "",
    user_agent: str = "",
    timeout: float = 30,
) -> dict[str, Any]:
    """Follow OAuth continue/callback then read https://chatgpt.com/api/auth/session.

    Returns a normalized credential dict suitable for Agent Identity / CPA:
      access_token, session_token, account_id, email, refresh_token?, id_token?, expires_at, raw_session
    """
    continue_url = str(continue_url or "").strip()
    ua = str(user_agent or "").strip() or (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    )
    nav_headers = {
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": ua,
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
    }
    api_headers = {
        "Accept": "application/json",
        "Accept-Language": "en-US,en;q=0.9",
        "User-Agent": ua,
        "Referer": f"{CHATGPT_BASE}/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
    }

    if continue_url:
        headers = dict(nav_headers)
        headers["Referer"] = f"{AUTH_BASE}/"
        headers["Sec-Fetch-Site"] = "cross-site"
        try:
            session.get(
                continue_url,
                headers=headers,
                allow_redirects=True,
                timeout=timeout,
                verify=False,
            )
        except Exception:
            pass

    # warm homepage for cookies
    try:
        headers = dict(nav_headers)
        headers["Sec-Fetch-Site"] = "none"
        session.get(
            f"{CHATGPT_BASE}/",
            headers=headers,
            allow_redirects=True,
            timeout=timeout,
            verify=False,
        )
    except Exception:
        pass

    try:
        resp = session.get(
            f"{CHATGPT_BASE}/api/auth/session",
            headers=api_headers,
            allow_redirects=True,
            timeout=timeout,
            verify=False,
        )
    except Exception as exc:
        return {"ok": False, "error": f"session_request_failed:{exc}"}

    if int(getattr(resp, "status_code", 0) or 0) != 200:
        body = ""
        try:
            body = (resp.text or "")[:240]
        except Exception:
            pass
        return {
            "ok": False,
            "error": f"session_http_{getattr(resp, 'status_code', None)}",
            "detail": body,
        }

    try:
        data = resp.json() if resp.text else {}
    except Exception:
        data = {}
    if not isinstance(data, dict) or not data:
        return {"ok": False, "error": "session_empty"}

    access = str(data.get("accessToken") or data.get("access_token") or "").strip()
    if not access:
        return {"ok": False, "error": "session_no_access_token", "raw_session": data}

    user = data.get("user") if isinstance(data.get("user"), dict) else {}
    account = data.get("account") if isinstance(data.get("account"), dict) else {}

    # account id: session.account.id or JWT claim
    account_id = str(account.get("id") or account.get("account_id") or "").strip()
    if not account_id:
        try:
            import base64
            import json as _json

            payload_part = access.split(".")[1]
            payload_part += "=" * (-len(payload_part) % 4)
            jwt_payload = _json.loads(base64.urlsafe_b64decode(payload_part))
            auth = jwt_payload.get("https://api.openai.com/auth") or {}
            if isinstance(auth, dict):
                account_id = str(auth.get("chatgpt_account_id") or "").strip()
            exp = jwt_payload.get("exp")
        except Exception:
            exp = None
    else:
        exp = None
        try:
            import base64
            import json as _json

            payload_part = access.split(".")[1]
            payload_part += "=" * (-len(payload_part) % 4)
            jwt_payload = _json.loads(base64.urlsafe_b64decode(payload_part))
            exp = jwt_payload.get("exp")
        except Exception:
            exp = None

    session_token = _cookie_from_session(
        session,
        "__Secure-next-auth.session-token",
        "chatgpt.com",
        ".chatgpt.com",
    )
    if not session_token:
        # some payloads expose it
        session_token = str(
            data.get("sessionToken") or data.get("session_token") or ""
        ).strip()

    email = str((user or {}).get("email") or "").strip()
    if not email:
        try:
            import base64
            import json as _json

            payload_part = access.split(".")[1]
            payload_part += "=" * (-len(payload_part) % 4)
            jwt_payload = _json.loads(base64.urlsafe_b64decode(payload_part))
            profile = jwt_payload.get("https://api.openai.com/profile") or {}
            if isinstance(profile, dict):
                email = str(profile.get("email") or "").strip()
        except Exception:
            pass

    return {
        "ok": True,
        "access_token": access,
        "session_token": session_token,
        "refresh_token": str(
            data.get("refreshToken") or data.get("refresh_token") or ""
        ).strip(),
        "id_token": str(data.get("idToken") or data.get("id_token") or "").strip(),
        "account_id": account_id,
        "email": email,
        "expires_at": exp,
        "expires": data.get("expires"),
        "user": user,
        "account": account,
        "auth_provider": data.get("authProvider") or data.get("auth_provider"),
        "raw_session": data,
        "source_type": "chatgpt_session",
    }


class ChatGPTWebEntry:
    """chatgpt.com -> csrf -> signin/openai -> authorize (pure HTTP)."""

    def __init__(
        self,
        email: str,
        *,
        proxy: str = "",
        log: Callable[[str], None] | None = None,
        timeout: float = 30,
        verbose: bool = False,
        screen_hint: str = "signup",
        extra_query: dict[str, str] | None = None,
    ):
        self.email = str(email or "").strip()
        self.proxy = str(proxy or "").strip()
        self._log_fn = log or (lambda _m: None)
        self.verbose = bool(verbose)
        self.timeout = float(timeout or 30)
        self.screen_hint = str(screen_hint or "signup").strip() or "signup"
        self.extra_query = {
            str(k): str(v)
            for k, v in dict(extra_query or {}).items()
            if str(k or "").strip() and str(v or "").strip()
        }
        self.profile = _pick_profile()
        self.session = self._build_session()
        self.device_id = ""
        self.csrf_token = ""
        self.authorize_url = ""
        self.final_url = ""
        self.page_type = ""

    def log(self, msg: str, *, force: bool = False) -> None:
        if force or self.verbose:
            self._log_fn(msg)

    def _build_session(self) -> requests.Session:
        session = requests.Session(
            impersonate=self.profile["impersonate"],
            timeout=self.timeout,
            verify=False,
        )
        if self.proxy:
            session.proxies = {"http": self.proxy, "https": self.proxy}
        session.headers.update(
            {
                "User-Agent": self.profile["user_agent"],
                "Accept-Language": "en-US,en;q=0.9",
                "sec-ch-ua": self.profile["sec_ch_ua"],
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
                "sec-ch-ua-arch": '"x86"',
                "sec-ch-ua-bitness": '"64"',
                "sec-ch-ua-model": '""',
                "sec-ch-ua-platform-version": '"15.0.0"',
                "sec-ch-ua-full-version": self.profile["sec_ch_ua_full_version"],
                "sec-ch-ua-full-version-list": self.profile["sec_ch_ua_full_version_list"],
            }
        )
        return session

    def _nav_headers(self, *, referer: str = "", site: str = "none") -> dict[str, str]:
        headers = {
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,image/apng,*/*;q=0.8,"
                "application/signed-exchange;v=b3;q=0.7"
            ),
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": site,
            "Sec-Fetch-User": "?1",
            "User-Agent": self.profile["user_agent"],
            "sec-ch-ua": self.profile["sec_ch_ua"],
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        }
        if referer:
            headers["Referer"] = referer
        return headers

    def _api_headers(self, *, referer: str, origin: str = "") -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Content-Type": "application/json",
            "Referer": referer,
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": self.profile["user_agent"],
            "sec-ch-ua": self.profile["sec_ch_ua"],
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        }
        if origin:
            headers["Origin"] = origin
        return headers

    def _get_cookie(self, name: str, *domains: str) -> str:
        for domain in domains:
            try:
                val = self.session.cookies.get(name, domain=domain)
                if val:
                    return str(val)
            except Exception:
                continue
        try:
            val = self.session.cookies.get(name)
            if val:
                return str(val)
        except Exception:
            pass
        return ""

    def _sync_device_id(self, device_id: str) -> None:
        for domain in (
            "chatgpt.com",
            ".chatgpt.com",
            "auth.openai.com",
            ".auth.openai.com",
            ".openai.com",
        ):
            try:
                self.session.cookies.set("oai-did", device_id, domain=domain, path="/")
            except Exception:
                continue

    def _request(self, method: str, url: str, *, retries: int = 3, **kwargs):
        last_exc: Exception | None = None
        last_resp = None
        for attempt in range(1, max(1, retries) + 1):
            try:
                resp = self.session.request(method, url, timeout=self.timeout, **kwargs)
            except Exception as exc:
                last_exc = exc
                if attempt >= retries:
                    raise
                time.sleep(0.8 * attempt)
                continue
            last_resp = resp
            status = int(getattr(resp, "status_code", 0) or 0)
            if status in {408, 409, 425, 429} or 500 <= status < 600:
                if attempt < retries:
                    time.sleep(0.8 * attempt)
                    continue
            return resp
        if last_resp is not None:
            return last_resp
        if last_exc:
            raise last_exc
        raise RuntimeError("request failed")

    def execute(self) -> ChatGPTWebEntryResult:
        result = ChatGPTWebEntryResult(profile=dict(self.profile), session=self.session)
        if not self.email or "@" not in self.email:
            result.error = "invalid email"
            return result

        resp = self._request(
            "GET",
            f"{CHATGPT_BASE}/",
            headers=self._nav_headers(site="none"),
            allow_redirects=True,
        )
        if _is_cf_challenge(resp):
            result.error = (
                f"chatgpt.com 首页被 Cloudflare 拦截 status={resp.status_code} "
                f"cf-ray={resp.headers.get('cf-ray', '')}"
            )
            return result
        if int(getattr(resp, "status_code", 0) or 0) >= 400:
            result.error = f"chatgpt homepage http_{resp.status_code}"
            return result

        did = self._get_cookie("oai-did", "chatgpt.com", ".chatgpt.com")
        self.device_id = did or str(uuid.uuid4())
        self._sync_device_id(self.device_id)

        resp = self._request(
            "GET",
            f"{CHATGPT_BASE}/api/auth/csrf",
            headers=self._api_headers(referer=f"{CHATGPT_BASE}/"),
            allow_redirects=True,
        )
        if _is_cf_challenge(resp) or int(getattr(resp, "status_code", 0) or 0) != 200:
            result.error = f"csrf failed status={getattr(resp, 'status_code', None)}"
            return result
        try:
            data = resp.json()
        except Exception:
            data = {}
        self.csrf_token = str((data or {}).get("csrfToken") or "").strip()
        if not self.csrf_token:
            result.error = "csrfToken empty"
            return result

        query = {
            "prompt": "login",
            "ext-oai-did": self.device_id,
            "auth_session_logging_id": str(uuid.uuid4()),
            "ext-passkey-client-capabilities": "1111",
            "screen_hint": self.screen_hint,
            "login_hint": self.email,
        }
        if self.extra_query:
            query.update(self.extra_query)
        signin_url = f"{CHATGPT_BASE}/api/auth/signin/openai?{urlencode(query)}"
        headers = self._api_headers(referer=f"{CHATGPT_BASE}/", origin=CHATGPT_BASE)
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Accept"] = "application/json"
        form = {
            "callbackUrl": f"{CHATGPT_BASE}/",
            "csrfToken": self.csrf_token,
            "json": "true",
        }
        resp = self._request(
            "POST",
            signin_url,
            headers=headers,
            data=form,
            allow_redirects=True,
        )
        if _is_cf_challenge(resp) or int(getattr(resp, "status_code", 0) or 0) >= 400:
            body = ""
            try:
                body = (resp.text or "")[:220]
            except Exception:
                pass
            result.error = (
                f"signin failed status={getattr(resp, 'status_code', None)} body={body}"
            )
            return result
        try:
            data = resp.json()
        except Exception:
            data = {}
        self.authorize_url = str((data or {}).get("url") or "").strip()
        if not self.authorize_url:
            result.error = (
                f"signin missing authorize url: "
                f"{json.dumps(data, ensure_ascii=False)[:240]}"
            )
            return result

        headers = self._nav_headers(referer=f"{CHATGPT_BASE}/", site="cross-site")
        resp = self._request(
            "GET",
            self.authorize_url,
            headers=headers,
            allow_redirects=True,
        )
        self.final_url = str(getattr(resp, "url", "") or "")
        if _is_cf_challenge(resp):
            result.error = (
                f"authorize CF challenge status={resp.status_code} "
                f"cf-ray={resp.headers.get('cf-ray', '')} url={self.final_url[:120]}"
            )
            result.authorize_url = self.authorize_url
            result.device_id = self.device_id
            return result

        final = self.final_url.lower()
        if "create-account/password" in final:
            self.page_type = "create_account_password"
        elif "log-in/password" in final or "login/password" in final:
            self.page_type = "login_password"
        elif "email-verification" in final:
            self.page_type = "email_otp_verification"
        elif "about-you" in final:
            self.page_type = "about_you"
        else:
            path = urlparse(self.final_url).path or ""
            if "api/accounts/authorize" in path or path in {"", "/error"}:
                result.error = f"authorize landed intermediate page: {self.final_url[:180]}"
                result.authorize_url = self.authorize_url
                result.device_id = self.device_id
                return result
            self.page_type = path.strip("/") or "unknown"

        did2 = self._get_cookie(
            "oai-did",
            "auth.openai.com",
            ".auth.openai.com",
            "chatgpt.com",
            ".chatgpt.com",
        )
        if did2:
            self.device_id = did2
            self._sync_device_id(self.device_id)

        result.success = True
        result.device_id = self.device_id
        result.authorize_url = self.authorize_url
        result.final_url = self.final_url
        result.page_type = self.page_type
        result.session = self.session
        self.log(f"官网入口完成 page={self.page_type or '?'}", force=True)
        return result

    def close(self) -> None:
        try:
            self.session.close()
        except Exception:
            pass