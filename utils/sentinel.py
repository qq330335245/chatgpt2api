"""OpenAI Sentinel Token (PoW) ??????????

???????????? sentinel token ????
"""
from __future__ import annotations

import base64
import json
import os
import random
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from curl_cffi.requests import Session


class SentinelTokenGenerator:
    """Sentinel Token ????PoW - Proof of Work??"""
    MAX_ATTEMPTS = 500_000
    ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"

    def __init__(self, device_id: str, ua: str):
        self.device_id = device_id
        self.user_agent = ua
        self.sid = str(uuid.uuid4())

    @staticmethod
    def _fnv1a_32(text: str) -> str:
        h = 2166136261
        for ch in text:
            h ^= ord(ch)
            h = (h * 16777619) & 0xFFFFFFFF
        h ^= h >> 16
        h = (h * 2246822507) & 0xFFFFFFFF
        h ^= h >> 13
        h = (h * 3266489909) & 0xFFFFFFFF
        h ^= h >> 16
        return format(h & 0xFFFFFFFF, "08x")

    def _get_config(self) -> list:
        perf_now = random.uniform(1000, 50000)
        return [
            "1920x1080",
            time.strftime("%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)", time.gmtime()),
            4294705152,
            random.random(),
            self.user_agent,
            "https://sentinel.openai.com/sentinel/20260124ceb8/sdk.js",
            None,
            None,
            "en-US",
            random.random(),
            random.choice(["vendorSub-undefined", "plugins-undefined", "mimeTypes-undefined", "hardwareConcurrency-undefined"]),
            random.choice(["location", "implementation", "URL", "documentURI", "compatMode"]),
            random.choice(["Object", "Function", "Array", "Number", "parseFloat", "undefined"]),
            perf_now,
            self.sid,
            "",
            random.choice([4, 8, 12, 16]),
            time.time() * 1000 - perf_now,
        ]

    @staticmethod
    def _b64(data) -> str:
        return base64.b64encode(json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).decode("ascii")

    def generate_requirements_token(self) -> str:
        data = self._get_config()
        data[3] = 1
        data[9] = round(random.uniform(5, 50))
        return "gAAAAAC" + self._b64(data)

    def generate_token(self, seed: str, difficulty: str) -> str:
        start = time.time()
        data = self._get_config()
        difficulty = str(difficulty or "0")
        for i in range(self.MAX_ATTEMPTS):
            data[3] = i
            data[9] = round((time.time() - start) * 1000)
            payload = self._b64(data)
            if self._fnv1a_32(seed + payload)[: len(difficulty)] <= difficulty:
                return "gAAAAAB" + payload + "~S"
        return "gAAAAAB" + self.ERROR_PREFIX + self._b64(str(None))


# ?? ?? User-Agent ? sec-ch-ua ??????????????????????????????
DEFAULT_SENTINEL_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/145.0.0.0 Safari/537.36"
)
DEFAULT_SENTINEL_SEC_CH_UA = '"Chromium";v="145", "Google Chrome";v="145", "Not/A)Brand";v="99"'

_FLOW_PAGE_URLS = {
    "oauth_create_account": "https://auth.openai.com/about-you",
    "username_password_create": "https://auth.openai.com/create-account/password",
    "password_verify": "https://auth.openai.com/log-in/password",
    "authorize_continue": "https://auth.openai.com/",
}


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _node_probe_script() -> Path:
    override = str(os.environ.get("SENTINEL_NODE_PROBE") or "").strip()
    if override:
        return Path(override)
    return _project_root() / "scripts" / "sentinel_node_probe.js"


def _node_binary() -> str:
    override = str(os.environ.get("SENTINEL_NODE_PATH") or "").strip()
    if override:
        return override
    return shutil.which("node") or "node"


def _truthy_env(name: str, default: bool = True) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return str(raw).strip().lower() not in {"0", "false", "no", "off", ""}


def _page_url_for_flow(flow: str, page_url: str = "") -> str:
    explicit = str(page_url or "").strip()
    if explicit:
        return explicit
    return _FLOW_PAGE_URLS.get(str(flow or "").strip(), "")


def _oai_sc_from_token_payload(payload: dict[str, Any]) -> str:
    c_value = str(payload.get("c") or "").strip()
    return f"0{c_value}" if c_value else ""


def _validate_node_token_payload(payload: dict[str, Any], flow: str) -> None:
    if payload.get("e"):
        raise RuntimeError(f"sentinel_node_token_error_{str(payload.get('e') or '')[:120]}")
    missing = [key for key in ("p", "t", "c", "id", "flow") if not str(payload.get(key) or "").strip()]
    if missing:
        raise RuntimeError(f"sentinel_node_token_missing_{','.join(missing)}")
    token_flow = str(payload.get("flow") or "").strip()
    if token_flow and flow and token_flow != flow:
        raise RuntimeError(f"sentinel_node_token_flow_mismatch_{token_flow}")


def build_sentinel_token_via_node(
    device_id: str,
    flow: str,
    *,
    user_agent: str = "",
    page_url: str = "",
    timeout_seconds: int = 70,
) -> tuple[str, str]:
    """???? Sentinel SDK?Node ????????? t ??? token?"""
    script = _node_probe_script()
    if not script.exists():
        raise FileNotFoundError(f"missing sentinel node probe: {script}")

    command = [
        _node_binary(),
        str(script),
        "--flow",
        str(flow or "").strip(),
        "--device-id",
        str(device_id or "").strip(),
        "--full",
    ]
    resolved_page_url = _page_url_for_flow(flow, page_url)
    if resolved_page_url:
        command.extend(["--page-url", resolved_page_url])
    if user_agent:
        command.extend(["--user-agent", user_agent])

    completed = subprocess.run(
        command,
        cwd=str(_project_root()),
        text=True,
        capture_output=True,
        timeout=max(5, int(timeout_seconds or 70)),
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise RuntimeError(f"sentinel_node_probe_failed_{completed.returncode}: {detail[:300]}")

    raw = str(completed.stdout or "").strip()
    try:
        payload = json.loads(raw)
    except Exception as exc:
        raise RuntimeError(f"sentinel_node_probe_invalid_json: {raw[:200]}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("sentinel_node_probe_invalid_payload")

    # ???? --bundle-output ?? {token: "..."} ????
    if "token" in payload and not payload.get("p"):
        token_raw = str(payload.get("token") or "").strip()
        payload = json.loads(token_raw)

    if not isinstance(payload, dict):
        raise RuntimeError("sentinel_node_probe_invalid_token_object")

    _validate_node_token_payload(payload, flow)
    if not str(payload.get("id") or "").strip():
        payload["id"] = device_id
    if not str(payload.get("flow") or "").strip():
        payload["flow"] = flow

    sentinel_value = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return sentinel_value, _oai_sc_from_token_payload(payload)


def build_sentinel_token_python(
    session: "Session",
    device_id: str,
    flow: str,
    *,
    user_agent: str = "",
    sec_ch_ua: str = "",
) -> tuple[str, str]:
    """? Python ???????? p/c?t ?????"""
    ua = user_agent or DEFAULT_SENTINEL_USER_AGENT
    ch_ua = sec_ch_ua or DEFAULT_SENTINEL_SEC_CH_UA
    generator = SentinelTokenGenerator(device_id, ua)
    resp = session.post(
        "https://sentinel.openai.com/backend-api/sentinel/req",
        data=json.dumps({"p": generator.generate_requirements_token(), "id": device_id, "flow": flow}),
        headers={
            "Content-Type": "text/plain;charset=UTF-8",
            "Referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html",
            "Origin": "https://sentinel.openai.com",
            "User-Agent": ua,
            "sec-ch-ua": ch_ua,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        },
        timeout=20,
        verify=False,
    )

    try:
        data = resp.json() if resp.text else {}
    except Exception:
        fallback = json.dumps(
            {"p": generator.generate_requirements_token(), "t": "", "c": "", "id": device_id, "flow": flow},
            separators=(",", ":"),
        )
        return fallback, ""

    token = str(data.get("token") or "").strip()
    if resp.status_code != 200 or not token:
        raise RuntimeError(f"sentinel_req_failed_{resp.status_code}")
    pow_data = data.get("proofofwork") or {}
    p_value = (
        generator.generate_token(str(pow_data.get("seed") or ""), str(pow_data.get("difficulty") or "0"))
        if pow_data.get("required") and pow_data.get("seed")
        else generator.generate_requirements_token()
    )
    sentinel_value = json.dumps({"p": p_value, "t": "", "c": token, "id": device_id, "flow": flow}, separators=(",", ":"))
    # oai-sc cookie = "0" + sentinel token "c" value (the challenge token from the server)
    oai_sc_value = "0" + token
    return sentinel_value, oai_sc_value


def build_sentinel_token(
    session: "Session",
    device_id: str,
    flow: str,
    *,
    user_agent: str = "",
    sec_ch_ua: str = "",
    page_url: str = "",
    prefer_node: bool | None = None,
) -> tuple[str, str]:
    """?? sentinel token ??? (sentinel_header_value, oai_sc_cookie_value)?

    ????? Node SDK ??????? t???????? Python ?????

    Args:
        session: curl_cffi Session ??
        device_id: ?? ID
        flow: ?????? "password_verify", "username_password_create" ??
        user_agent: ??? User-Agent ??
        sec_ch_ua: ??? sec-ch-ua ??
        page_url: ?????????? Node SDK ??
        prefer_node: ???? Node????? SENTINEL_USE_NODE??????

    Returns:
        (openai-sentinel-token header value, oai-sc cookie value) ??

    Raises:
        RuntimeError: sentinel ????
    """
    use_node = _truthy_env("SENTINEL_USE_NODE", True) if prefer_node is None else bool(prefer_node)
    if use_node:
        try:
            return build_sentinel_token_via_node(
                device_id,
                flow,
                user_agent=user_agent or DEFAULT_SENTINEL_USER_AGENT,
                page_url=page_url,
            )
        except Exception:
            # ?????????????? prefer_node=True ?????
            if prefer_node is True:
                raise

    return build_sentinel_token_python(
        session,
        device_id,
        flow,
        user_agent=user_agent,
        sec_ch_ua=sec_ch_ua,
    )
