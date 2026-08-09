"""iCloud Hide My Email client helpers."""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass
from http.cookies import SimpleCookie
from typing import Any, Dict, Iterable, List, Mapping, Optional

from curl_cffi import requests as cffi_requests


ICLOUD_HME_REQUIRED_COOKIES = (
    "X-APPLE-WEBAUTH-USER",
    "X-APPLE-WEBAUTH-TOKEN",
    "X-APPLE-DS-WEB-SESSION-TOKEN",
)
ICLOUD_HME_CONNECTED_KEY = "icloud_hme_connected"
ICLOUD_HME_ANONYMOUS_ID_KEY = "icloud_hme_anonymous_id"
ICLOUD_HME_ALIAS_ACTIVE_KEY = "icloud_hme_alias_active"
ICLOUD_HME_SYNCED_AT_KEY = "icloud_hme_synced_at"

_ICLOUD_HME_PARAMS = {
    "clientBuildNumber": "2626Build17",
    "clientMasteringNumber": "2626Build17",
    "clientId": "auto-script",
}
_ICLOUD_HME_BASE_URL = "https://p41-maildomainws.icloud.com"
_ICLOUD_HME_GENERATOR_PARAMS = {
    "clientBuildNumber": "2626Build17",
    "clientMasteringNumber": "2626Build17",
    "clientId": "",
}
_ICLOUD_HME_GENERATOR_BASE_URL = "https://p41-maildomainws.icloud.com"
_ICLOUD_HME_HOST_FALLBACKS = (
    "https://p41-maildomainws.icloud.com",
    "https://p68-maildomainws.icloud.com",
    "https://p158-maildomainws.icloud.com",
)
_ICLOUD_HME_HEADERS = {
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Content-Type": "text/plain",
    "Origin": "https://www.icloud.com",
    "Referer": "https://www.icloud.com/",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-site",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    ),
    "sec-ch-ua": '"Chromium";v="122", "Google Chrome";v="122", "Not(A:Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
}
_COOKIE_ASSIGNMENT_RE = re.compile(r"^\s*[A-Za-z_]\w*\s*=\s*", re.MULTILINE)
_DSID_RE = re.compile(r'(?:^|:)d=([^":;]+)')
_EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)


class ICloudHideMyEmailError(RuntimeError):
    """Raised when Apple Hide My Email operations fail."""


@dataclass(frozen=True)
class ICloudHideMyEmailAlias:
    anonymous_id: str
    email: str
    is_active: bool
    raw: Dict[str, Any]
    label: str = ""
    note: str = ""
    forward_to_email: str = ""


def _stringify_cookie_value(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _normalize_cookie_mapping(mapping: Mapping[str, Any]) -> Dict[str, str]:
    normalized: Dict[str, str] = {}
    for key, value in (mapping or {}).items():
        name = str(key or "").strip()
        if not name:
            continue
        cookie_value = _stringify_cookie_value(value)
        if cookie_value:
            normalized[name] = cookie_value
    return normalized


def get_icloud_hme_state(config: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    source = dict(config or {})
    anonymous_id = str(source.get(ICLOUD_HME_ANONYMOUS_ID_KEY) or "").strip()
    synced_at = str(source.get(ICLOUD_HME_SYNCED_AT_KEY) or "").strip() or None
    alias_active = source.get(ICLOUD_HME_ALIAS_ACTIVE_KEY)
    if alias_active is not None:
        alias_active = bool(alias_active)
    connected = bool(source.get(ICLOUD_HME_CONNECTED_KEY) and anonymous_id)
    return {
        "connected": connected,
        "anonymous_id": anonymous_id or None,
        "alias_active": alias_active,
        "synced_at": synced_at,
    }


def apply_icloud_hme_state(
    config: Optional[Mapping[str, Any]],
    *,
    anonymous_id: Any,
    is_active: Any,
    synced_at: Any,
) -> Dict[str, Any]:
    updated = dict(config or {})
    normalized_anonymous_id = str(anonymous_id or "").strip()
    updated[ICLOUD_HME_CONNECTED_KEY] = bool(normalized_anonymous_id)
    if normalized_anonymous_id:
        updated[ICLOUD_HME_ANONYMOUS_ID_KEY] = normalized_anonymous_id
    else:
        updated.pop(ICLOUD_HME_ANONYMOUS_ID_KEY, None)
    if is_active is None:
        updated.pop(ICLOUD_HME_ALIAS_ACTIVE_KEY, None)
    else:
        updated[ICLOUD_HME_ALIAS_ACTIVE_KEY] = bool(is_active)
    synced_text = str(synced_at or "").strip()
    if synced_text:
        updated[ICLOUD_HME_SYNCED_AT_KEY] = synced_text
    else:
        updated.pop(ICLOUD_HME_SYNCED_AT_KEY, None)
    return updated


def clear_icloud_hme_state(config: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    updated = dict(config or {})
    updated.pop(ICLOUD_HME_CONNECTED_KEY, None)
    updated.pop(ICLOUD_HME_ANONYMOUS_ID_KEY, None)
    updated.pop(ICLOUD_HME_ALIAS_ACTIVE_KEY, None)
    updated.pop(ICLOUD_HME_SYNCED_AT_KEY, None)
    return updated


def parse_icloud_account_cookies(raw: Any) -> Dict[str, str]:
    text = str(raw or "").strip()
    if not text:
        raise ICloudHideMyEmailError("iCloud account cookies are empty")

    parsers = (
        _parse_cookie_json_or_python_mapping,
        _parse_cookie_header_string,
        _parse_cookie_line_pairs,
    )
    last_error: Optional[Exception] = None
    for parser in parsers:
        try:
            cookies = parser(text)
        except Exception as exc:  # pragma: no cover - diagnostics only
            last_error = exc
            continue
        normalized = _normalize_cookie_mapping(cookies)
        if normalized:
            validate_icloud_account_cookies(normalized)
            return normalized

    if last_error:
        raise ICloudHideMyEmailError(
            f"Unable to parse iCloud account cookies: {last_error}"
        ) from last_error
    raise ICloudHideMyEmailError("Unable to parse iCloud account cookies")


def dump_icloud_account_cookies(cookies: Mapping[str, Any]) -> str:
    normalized = _normalize_cookie_mapping(cookies)
    validate_icloud_account_cookies(normalized)
    return json.dumps(normalized, ensure_ascii=False, sort_keys=True)


def validate_icloud_account_cookies(cookies: Mapping[str, Any]) -> None:
    normalized = _normalize_cookie_mapping(cookies)
    missing = [name for name in ICLOUD_HME_REQUIRED_COOKIES if not normalized.get(name)]
    if missing:
        raise ICloudHideMyEmailError(
            "Missing required iCloud account cookies: " + ", ".join(missing)
        )
    _ = derive_icloud_dsid(normalized)


def derive_icloud_dsid(cookies: Mapping[str, Any]) -> str:
    value = _stringify_cookie_value(cookies.get("X-APPLE-WEBAUTH-USER"))
    value = value.strip().strip('"').strip("'")
    match = _DSID_RE.search(value)
    if not match:
        raise ICloudHideMyEmailError("Unable to extract dsid from X-APPLE-WEBAUTH-USER")
    return match.group(1).strip()


def _parse_cookie_json_or_python_mapping(text: str) -> Dict[str, Any]:
    candidate = text
    assignment_match = _COOKIE_ASSIGNMENT_RE.match(candidate)
    if assignment_match:
        candidate = candidate[assignment_match.end():].strip()

    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        parsed = ast.literal_eval(candidate)

    if not isinstance(parsed, dict):
        raise ValueError("cookie mapping must be an object/dict")
    return dict(parsed)


def _parse_cookie_header_string(text: str) -> Dict[str, Any]:
    jar = SimpleCookie()
    jar.load(text)
    if not jar:
        raise ValueError("not a cookie header")
    return {name: morsel.value for name, morsel in jar.items()}


def _parse_cookie_line_pairs(text: str) -> Dict[str, Any]:
    cookies: Dict[str, Any] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if _COOKIE_ASSIGNMENT_RE.match(line):
            raise ValueError("not line based pairs")
        if "=" in line:
            name, value = line.split("=", 1)
        elif ":" in line:
            name, value = line.split(":", 1)
        else:
            raise ValueError(f"invalid cookie line: {line}")
        normalized_name = str(name or "").strip()
        normalized_value = str(value or "").strip()
        if normalized_name and normalized_value:
            cookies[normalized_name] = normalized_value
    if not cookies:
        raise ValueError("no cookie pairs found")
    return cookies


def _extract_response_error_message(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""

    error = payload.get("error")
    if isinstance(error, dict):
        message = str(error.get("errorMessage") or error.get("reason") or "").strip()
        if message:
            return message
    elif error:
        return str(error).strip()

    for key in ("message", "detail", "errorMessage", "reason"):
        message = str(payload.get(key) or "").strip()
        if message:
            return message
    return ""


def _extract_first_string_by_keys(payload: Any, keys: Iterable[str]) -> str:
    normalized_keys = {str(key or "").strip().lower() for key in keys if str(key or "").strip()}
    if not normalized_keys:
        return ""

    def visit(node: Any) -> str:
        if isinstance(node, dict):
            for key, value in node.items():
                if str(key or "").strip().lower() in normalized_keys:
                    text = str(value or "").strip()
                    if text:
                        return text
            for value in node.values():
                found = visit(value)
                if found:
                    return found
        elif isinstance(node, list):
            for value in node:
                found = visit(value)
                if found:
                    return found
        return ""

    return visit(payload)


def _extract_first_bool_by_keys(payload: Any, keys: Iterable[str]) -> Optional[bool]:
    normalized_keys = {str(key or "").strip().lower() for key in keys if str(key or "").strip()}
    if not normalized_keys:
        return None

    def visit(node: Any) -> Optional[bool]:
        if isinstance(node, dict):
            for key, value in node.items():
                if str(key or "").strip().lower() in normalized_keys:
                    if isinstance(value, bool):
                        return value
                    if value is None:
                        return None
                    text = str(value).strip().lower()
                    if text in {"true", "1", "yes", "on"}:
                        return True
                    if text in {"false", "0", "no", "off"}:
                        return False
            for value in node.values():
                found = visit(value)
                if found is not None:
                    return found
        elif isinstance(node, list):
            for value in node:
                found = visit(value)
                if found is not None:
                    return found
        return None

    return visit(payload)


def _extract_first_email(payload: Any) -> str:
    direct = _extract_first_string_by_keys(payload, ("hme", "email", "alias", "address"))
    if direct and "@" in direct:
        return direct.strip().lower()

    def visit(node: Any) -> str:
        if isinstance(node, dict):
            for value in node.values():
                found = visit(value)
                if found:
                    return found
        elif isinstance(node, list):
            for value in node:
                found = visit(value)
                if found:
                    return found
        elif isinstance(node, str):
            match = _EMAIL_RE.search(node)
            if match:
                return match.group(0).strip().lower()
        return ""

    return visit(payload)


def _ensure_payload_not_failed(payload: Dict[str, Any], *, action: str) -> None:
    if not isinstance(payload, dict):
        raise ICloudHideMyEmailError(f"Apple HME {action} returned an invalid payload")

    error = payload.get("error")
    if error:
        message = _extract_response_error_message(payload) or str(error).strip() or "unknown error"
        raise ICloudHideMyEmailError(f"Apple HME {action} failed: {message}")

    if payload.get("success") is False:
        message = _extract_response_error_message(payload) or "unknown error"
        raise ICloudHideMyEmailError(f"Apple HME {action} failed: {message}")


class ICloudHideMyEmailClient:
    """Thin Apple Hide My Email API client using authenticated session cookies."""

    def __init__(
        self,
        cookies: Mapping[str, Any],
        *,
        session: Any = None,
        timeout: float = 20.0,
        impersonate: str = "chrome124",
    ) -> None:
        normalized = _normalize_cookie_mapping(cookies)
        validate_icloud_account_cookies(normalized)
        self.cookies = normalized
        self.dsid = derive_icloud_dsid(normalized)
        self.timeout = max(float(timeout or 20.0), 1.0)
        self._owns_session = session is None
        self.session = session or cffi_requests.Session(
            impersonate=impersonate,
            headers=dict(_ICLOUD_HME_HEADERS),
        )

    def close(self) -> None:
        if self._owns_session and self.session is not None:
            try:
                self.session.close()
            except Exception:
                pass

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: Optional[Mapping[str, Any]] = None,
        base_url: Optional[str] = None,
        params_override: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        url = f"{str(base_url or _ICLOUD_HME_BASE_URL).rstrip('/')}{path}"
        params = dict(_ICLOUD_HME_PARAMS)
        if params_override:
            params.update(dict(params_override))
        params["dsid"] = self.dsid
        kwargs: Dict[str, Any] = {
            "cookies": self.cookies,
            "params": params,
            "timeout": self.timeout,
        }
        if payload is not None:
            kwargs["data"] = json.dumps(dict(payload), ensure_ascii=False)

        response = self.session.request(method.upper(), url, **kwargs)
        response_text = str(getattr(response, "text", "") or "").strip()
        try:
            data = response.json()
        except Exception:
            data = None

        if int(getattr(response, "status_code", 0) or 0) >= 400:
            message = _extract_response_error_message(data) or response_text[:300] or "unknown error"
            raise ICloudHideMyEmailError(
                f"Apple HME request failed: HTTP {response.status_code} - {message}"
            )

        if data is None:
            raise ICloudHideMyEmailError("Apple HME returned a non-JSON response")

        return data

    def list_aliases(
        self,
        *,
        base_url: Optional[str] = None,
        params_override: Optional[Mapping[str, Any]] = None,
    ) -> List[ICloudHideMyEmailAlias]:
        payload = self._request(
            "GET",
            "/v2/hme/list",
            base_url=base_url,
            params_override=params_override,
        )
        _ensure_payload_not_failed(payload, action="list aliases")
        result = payload.get("result")
        aliases = result.get("hmeEmails") if isinstance(result, dict) else None
        if not isinstance(aliases, list):
            raise ICloudHideMyEmailError("Apple HME list response is missing hmeEmails")

        normalized_aliases: List[ICloudHideMyEmailAlias] = []
        for entry in aliases:
            if not isinstance(entry, dict):
                continue
            anonymous_id = str(entry.get("anonymousId") or "").strip()
            email = str(entry.get("hme") or "").strip().lower()
            if not anonymous_id or not email:
                continue
            normalized_aliases.append(
                ICloudHideMyEmailAlias(
                    anonymous_id=anonymous_id,
                    email=email,
                    is_active=bool(entry.get("isActive")),
                    raw=dict(entry),
                    label=str(entry.get("label") or "").strip(),
                    note=str(entry.get("note") or "").strip(),
                    forward_to_email=str(entry.get("forwardToEmail") or "").strip().lower(),
                )
            )
        return normalized_aliases

    def find_alias(self, anonymous_id: Any) -> Optional[ICloudHideMyEmailAlias]:
        normalized = str(anonymous_id or "").strip()
        if not normalized:
            return None
        for alias in self.list_aliases():
            if alias.anonymous_id == normalized:
                return alias
        return None

    def generate_alias_candidate(self, *, lang_code: str = "en-us") -> str:
        payload = self._request(
            "POST",
            "/v1/hme/generate",
            payload={"langCode": str(lang_code or "en-us").strip() or "en-us"},
            base_url=_ICLOUD_HME_GENERATOR_BASE_URL,
            params_override=_ICLOUD_HME_GENERATOR_PARAMS,
        )
        _ensure_payload_not_failed(payload, action="generate alias")
        alias_email = _extract_first_email(payload)
        if not alias_email:
            raise ICloudHideMyEmailError(
                "Apple HME generate response did not contain an alias email"
            )
        return alias_email

    def reserve_alias(
        self,
        email: Any,
        *,
        label: Optional[str] = None,
        note: Optional[str] = None,
    ) -> ICloudHideMyEmailAlias:
        alias_email = str(email or "").strip().lower()
        if not alias_email or "@" not in alias_email:
            raise ICloudHideMyEmailError("Apple HME reserve requires a valid alias email")

        payload = self._request(
            "POST",
            "/v1/hme/reserve",
            payload={
                "hme": alias_email,
                "label": str(label or "").strip(),
                "note": str(note or "").strip(),
            },
            base_url=_ICLOUD_HME_GENERATOR_BASE_URL,
            params_override=_ICLOUD_HME_GENERATOR_PARAMS,
        )
        _ensure_payload_not_failed(payload, action="reserve alias")

        for base_url, params_override in (
            (None, None),
            (_ICLOUD_HME_GENERATOR_BASE_URL, _ICLOUD_HME_GENERATOR_PARAMS),
        ):
            try:
                aliases = self.list_aliases(
                    base_url=base_url,
                    params_override=params_override,
                )
            except Exception:
                continue
            for alias in aliases:
                if alias.email == alias_email:
                    return alias

        anonymous_id = _extract_first_string_by_keys(payload, ("anonymousId", "anonymous_id"))
        if not anonymous_id:
            raise ICloudHideMyEmailError(
                "Apple HME reserve succeeded but anonymousId could not be parsed"
            )

        is_active = _extract_first_bool_by_keys(payload, ("isActive", "active"))
        return ICloudHideMyEmailAlias(
            anonymous_id=anonymous_id,
            email=alias_email,
            is_active=True if is_active is None else bool(is_active),
            raw=dict(payload),
        )

    def create_alias(
        self,
        *,
        label: Optional[str] = None,
        note: Optional[str] = None,
        lang_code: str = "en-us",
    ) -> ICloudHideMyEmailAlias:
        alias_email = self.generate_alias_candidate(lang_code=lang_code)
        return self.reserve_alias(
            alias_email,
            label=label or "chatgpt2api",
            note=note or "Generated by chatgpt2api iCloud alias manager",
        )

    def update_metadata(
        self,
        anonymous_id: Any,
        *,
        label: Optional[str] = None,
        note: Optional[str] = None,
        base_url: Optional[str] = None,
        params_override: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update alias label/note via POST /v1/hme/updateMetaData."""
        normalized = str(anonymous_id or "").strip()
        if not normalized:
            raise ICloudHideMyEmailError("anonymousId cannot be empty")
        body: Dict[str, Any] = {"anonymousId": normalized}
        if label is not None:
            body["label"] = str(label)
        if note is not None:
            body["note"] = str(note)
        if "label" not in body and "note" not in body:
            raise ICloudHideMyEmailError("update_metadata requires label and/or note")
        hosts = []
        if base_url:
            hosts.append(str(base_url).rstrip("/"))
        for host in _ICLOUD_HME_HOST_FALLBACKS:
            if host not in hosts:
                hosts.append(host)
        last_exc: Optional[Exception] = None
        for host in hosts:
            try:
                payload = self._request(
                    "POST",
                    "/v1/hme/updateMetaData",
                    payload=body,
                    base_url=host,
                    params_override=params_override,
                )
                self._ensure_action_success(payload, action="update metadata")
                return payload if isinstance(payload, dict) else {"success": True, "result": payload}
            except Exception as exc:
                last_exc = exc
                continue
        raise ICloudHideMyEmailError(f"Apple HME update metadata failed: {last_exc}") from last_exc

    def deactivate_alias(self, anonymous_id: Any) -> None:
        normalized = str(anonymous_id or "").strip()
        if not normalized:
            raise ICloudHideMyEmailError("anonymousId cannot be empty")
        payload = self._request(
            "POST",
            "/v1/hme/deactivate",
            payload={"anonymousId": normalized},
        )
        self._ensure_action_success(payload, action="deactivate alias")

    def delete_alias(self, anonymous_id: Any) -> None:
        normalized = str(anonymous_id or "").strip()
        if not normalized:
            raise ICloudHideMyEmailError("anonymousId cannot be empty")
        payload = self._request(
            "POST",
            "/v1/hme/delete",
            payload={"anonymousId": normalized},
        )
        self._ensure_action_success(payload, action="delete alias")

    @staticmethod
    def _ensure_action_success(payload: Dict[str, Any], *, action: str) -> None:
        _ensure_payload_not_failed(payload, action=action)
        if bool(payload.get("success")):
            return
        if payload.get("result") is not None:
            return
        message = _extract_response_error_message(payload) or "unknown error"
        raise ICloudHideMyEmailError(f"Apple HME {action} failed: {message}")


def build_icloud_hme_client_from_settings(settings: Any) -> ICloudHideMyEmailClient:
    raw = ""
    secret = getattr(settings, "icloud_account_cookies", None)
    if secret:
        try:
            raw = secret.get_secret_value()
        except Exception:
            raw = str(secret)
    cookies = parse_icloud_account_cookies(raw)
    return ICloudHideMyEmailClient(cookies)
