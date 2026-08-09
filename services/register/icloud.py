# -*- coding: utf-8 -*-
"""Standalone iCloud Hide My Email provider (no codex-console dependency).

Modes for obtaining a register address:
1) Local lease inventory (hot path): free -> leased -> registered
2) On-demand Apple list sync (single-flight) to replenish inventory
3) Create new HME alias only when inventory has no free aliases
Cloud note tags remain cross-device truth; local inventory is same-machine SoT.

Receive codes via Cloudflare Temp-Mail admin inbox (HME forward target).
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from services.register import icloud_hme as hme
from services.register import icloud_note_tags as note_tags
from services.register import icloud_pool as alias_pool

CancelCb = Optional[Callable[[], bool]]
LogFn = Optional[Callable[[str], None]]
HttpGet = Callable[..., Any]

DEFAULT_USED_FILE = "icloud_used_emails.json"
_used_lock = threading.Lock()
_code_claim_lock = threading.Lock()
_claimed_mail_ids: Set[str] = set()
_email_anon_cache: Dict[str, str] = {}
DEFAULT_PLATFORM = "chatgpt"
EMAIL_LINE_RE = re.compile(
    r"([A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,})",
    re.I,
)

def _project_root() -> str:
    try:
        from services.config import DATA_DIR
        return str(DATA_DIR)
    except Exception:
        return os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "data",
        )

def _resolve_path(path: str = "") -> str:
    raw = (path or DEFAULT_USED_FILE).strip() or DEFAULT_USED_FILE
    if os.path.isabs(raw):
        return raw
    return os.path.join(_project_root(), raw)

def _norm_email(value: Any) -> str:
    return str(value or "").strip().lower()

def load_used_emails(path: str = "") -> Set[str]:
    file_path = _resolve_path(path)
    try:
        if os.path.isfile(file_path):
            data = json.loads(Path(file_path).read_text(encoding="utf-8"))
            if isinstance(data, list):
                return {_norm_email(x) for x in data if _norm_email(x)}
            if isinstance(data, dict):
                emails = data.get("emails") or data.get("used") or data.get("registered") or []
                if isinstance(emails, list):
                    return {_norm_email(x) for x in emails if _norm_email(x)}
    except Exception:
        pass
    return set()

def save_used_emails(emails: Set[str], path: str = "") -> None:
    file_path = _resolve_path(path)
    parent = os.path.dirname(file_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    payload = {
        "emails": sorted({_norm_email(x) for x in emails if _norm_email(x)}),
        "count": len(emails),
    }
    Path(file_path).write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

def record_registered(
    email: str,
    path: str = "",
    *,
    cookies_raw: str = "",
    anonymous_id: str = "",
    platform: str = DEFAULT_PLATFORM,
    cloud_mark: bool = True,
    use_local_used: bool = False,
    timeout: float = 25.0,
    log_callback: LogFn = None,
    lease_id: str = "",
    inventory_path: str = "",
    coordination_mode: str = "local_fast",
) -> None:
    """Commit lease / mark registered. No Apple list on this path."""
    addr = _norm_email(email)
    if not addr and not str(lease_id or "").strip():
        return
    if use_local_used and addr:
        with _used_lock:
            used = load_used_emails(path)
            if addr not in used:
                used.add(addr)
                save_used_emails(used, path)
    try:
        commit_registration(
            email=addr,
            lease_id=str(lease_id or ""),
            cookies_raw=str(cookies_raw or ""),
            platform=platform,
            cloud_mark=cloud_mark,
            inventory_path=inventory_path,
            coordination_mode=coordination_mode,
            timeout=timeout,
            log_callback=log_callback,
            anonymous_id=str(anonymous_id or ""),
        )
    except Exception as exc:
        if log_callback:
            log_callback(f"[!] 注册成功后提交 iCloud 租约失败: {exc}")

def is_registered(email: str, path: str = "") -> bool:
    addr = _norm_email(email)
    if not addr:
        return False
    with _used_lock:
        return addr in load_used_emails(path)

def collect_emails_from_accounts_files(
    root: str = "",
    *,
    patterns: Optional[Iterable[str]] = None,
) -> Set[str]:
    """Scan local accounts_*.txt / mail_credentials.txt for already registered emails."""
    base = root or _project_root()
    found: Set[str] = set()
    names = list(patterns or ("accounts_*.txt", "mail_credentials.txt"))
    root_path = Path(base)
    files: List[Path] = []
    for pat in names:
        files.extend(root_path.glob(pat))
    for fp in files:
        try:
            text = fp.read_text(encoding="utf-8-sig", errors="ignore")
        except Exception:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # accounts: email----password----sso
            if "----" in line:
                email = _norm_email(line.split("----", 1)[0])
                if email and "@" in email:
                    found.add(email)
                continue
            m = EMAIL_LINE_RE.search(line)
            if m:
                found.add(_norm_email(m.group(1)))
    return found

def sync_used_from_local_accounts(path: str = "", root: str = "") -> Set[str]:
    """Merge accounts_*.txt emails into used file; return full used set."""
    with _used_lock:
        used = load_used_emails(path)
        before = len(used)
        used |= collect_emails_from_accounts_files(root=root)
        if len(used) != before:
            save_used_emails(used, path)
        return set(used)

def list_aliases(
    cookies_raw: str,
    *,
    timeout: float = 25.0,
    active_only: bool = True,
) -> List[Dict[str, Any]]:
    """List Hide My Email aliases from Apple. Returns list of dicts."""
    cookies = hme.parse_icloud_account_cookies(cookies_raw)
    client = hme.ICloudHideMyEmailClient(cookies, timeout=timeout)
    try:
        aliases = client.list_aliases()
    finally:
        client.close()
    out: List[Dict[str, Any]] = []
    for item in aliases:
        if active_only and not bool(item.is_active):
            continue
        email = _norm_email(item.email)
        if not email:
            continue
        out.append(
            {
                "email": email,
                "anonymous_id": str(item.anonymous_id or "").strip(),
                "is_active": bool(item.is_active),
                "label": str(getattr(item, "label", "") or "").strip(),
                "note": str(getattr(item, "note", "") or "").strip(),
                "forward_to_email": str(getattr(item, "forward_to_email", "") or "").strip(),
            }
        )
    # stable order
    out.sort(key=lambda x: x["email"])
    return out

def _mark_cloud_platform(
    cookies_raw: str,
    anonymous_id: str,
    *,
    platform: str = DEFAULT_PLATFORM,
    current_note: str = "",
    timeout: float = 25.0,
    log_callback: LogFn = None,
) -> str:
    """Write platform tag into HME note (comma-separated). Returns new note text."""
    anon = str(anonymous_id or "").strip()
    if not anon:
        return str(current_note or "")
    new_note = note_tags.note_add_platform(current_note, platform)
    old_note = note_tags.format_note_tags(note_tags.parse_note_tags(current_note))
    if new_note == old_note:
        return new_note
    cookies = hme.parse_icloud_account_cookies(cookies_raw)
    client = hme.ICloudHideMyEmailClient(cookies, timeout=timeout)
    try:
        client.update_metadata(anon, note=new_note)
    finally:
        client.close()
    if log_callback:
        log_callback(f"[*] iCloud note 已标记平台 [{platform}]: {new_note}")
    return new_note

def create_alias_address(
    cookies_raw: str,
    *,
    label: str = "chatgpt",
    note: str = "",
    timeout: float = 25.0,
) -> Tuple[str, str]:
    """Create a new Hide My Email alias. Returns (alias_email, anonymous_id)."""
    cookies = hme.parse_icloud_account_cookies(cookies_raw)
    client = hme.ICloudHideMyEmailClient(cookies, timeout=timeout)
    try:
        alias = client.create_alias(label=label, note=note)
    finally:
        client.close()
    email_addr = _norm_email(alias.email)
    anon = str(alias.anonymous_id or "").strip()
    if not email_addr or "@" not in email_addr:
        raise Exception("iCloud HME 未返回有效别名邮箱")
    return email_addr, anon

def acquire_lease(
    cookies_raw: str,
    *,
    inventory_path: str = "",
    used_file: str = "",
    reuse_aliases: bool = True,
    create_when_exhausted: bool = True,
    label: str = "chatgpt",
    note: str = "",
    platform: str = DEFAULT_PLATFORM,
    cloud_mark: bool = True,
    use_local_used: bool = False,
    coordination_mode: str = "local_fast",
    async_mark: bool = True,
    background_replenish: bool = True,
    low_watermark: int = alias_pool.DEFAULT_LOW_WATERMARK,
    high_watermark: int = alias_pool.DEFAULT_HIGH_WATERMARK,
    replenish_interval_sec: float = alias_pool.DEFAULT_REPLENISH_INTERVAL_SEC,
    create_per_cycle: int = alias_pool.DEFAULT_CREATE_PER_CYCLE,
    fail_cooldown_sec: float = alias_pool.DEFAULT_FAIL_COOLDOWN_SEC,
    fail_cooldown_max_sec: float = alias_pool.DEFAULT_FAIL_COOLDOWN_MAX_SEC,
    fail_cooldown_threshold: int = alias_pool.DEFAULT_FAIL_COOLDOWN_THRESHOLD,
    lease_ttl_sec: float = alias_pool.DEFAULT_LEASE_TTL_SEC,
    sync_interval_sec: float = alias_pool.DEFAULT_SYNC_INTERVAL_SEC,
    timeout: float = 25.0,
    log_callback: LogFn = None,
    accounts_root: str = "",
    owner: str = "",
):
    """Acquire an alias lease via local inventory pool."""
    cookies_raw = str(cookies_raw or "").strip()
    if not cookies_raw:
        raise Exception("未配置 icloud_cookies")

    _ = used_file, note, accounts_root, use_local_used

    service = alias_pool.get_lease_service(
        cookies_raw,
        inventory_path=inventory_path or alias_pool.DEFAULT_INVENTORY_FILE,
        platform=platform,
        label=label or platform,
        lease_ttl_sec=lease_ttl_sec,
        sync_interval_sec=sync_interval_sec,
        reuse_aliases=reuse_aliases,
        create_when_exhausted=create_when_exhausted,
        cloud_mark=cloud_mark,
        coordination_mode=coordination_mode,
        async_mark=async_mark,
        background_replenish=background_replenish,
        low_watermark=low_watermark,
        high_watermark=high_watermark,
        replenish_interval_sec=replenish_interval_sec,
        create_per_cycle=create_per_cycle,
        fail_cooldown_sec=fail_cooldown_sec,
        fail_cooldown_max_sec=fail_cooldown_max_sec,
        fail_cooldown_threshold=fail_cooldown_threshold,
        timeout=timeout,
        auto_start_background=True,
    )
    if log_callback:
        service.start_background(log_callback=log_callback)
    lease = service.acquire(owner=owner, log_callback=log_callback)
    _email_anon_cache[lease.email] = lease.anonymous_id
    return lease

def acquire_email_for_register(
    cookies_raw: str,
    *,
    used_file: str = "",
    reuse_aliases: bool = True,
    create_when_exhausted: bool = True,
    label: str = "chatgpt",
    note: str = "",
    platform: str = DEFAULT_PLATFORM,
    cloud_mark: bool = True,
    use_local_used: bool = False,
    timeout: float = 25.0,
    log_callback: LogFn = None,
    accounts_root: str = "",
    inventory_path: str = "",
    coordination_mode: str = "local_fast",
    async_mark: bool = True,
    background_replenish: bool = True,
    low_watermark: int = alias_pool.DEFAULT_LOW_WATERMARK,
    high_watermark: int = alias_pool.DEFAULT_HIGH_WATERMARK,
    replenish_interval_sec: float = alias_pool.DEFAULT_REPLENISH_INTERVAL_SEC,
    create_per_cycle: int = alias_pool.DEFAULT_CREATE_PER_CYCLE,
    lease_ttl_sec: float = alias_pool.DEFAULT_LEASE_TTL_SEC,
    sync_interval_sec: float = alias_pool.DEFAULT_SYNC_INTERVAL_SEC,
    owner: str = "",
):
    """Compatibility wrapper. Returns (email, anonymous_id, source)."""
    lease = acquire_lease(
        cookies_raw,
        inventory_path=inventory_path,
        used_file=used_file,
        reuse_aliases=reuse_aliases,
        create_when_exhausted=create_when_exhausted,
        label=label,
        note=note,
        platform=platform,
        cloud_mark=cloud_mark,
        use_local_used=use_local_used,
        coordination_mode=coordination_mode,
        async_mark=async_mark,
        background_replenish=background_replenish,
        low_watermark=low_watermark,
        high_watermark=high_watermark,
        replenish_interval_sec=replenish_interval_sec,
        create_per_cycle=create_per_cycle,
        lease_ttl_sec=lease_ttl_sec,
        sync_interval_sec=sync_interval_sec,
        timeout=timeout,
        log_callback=log_callback,
        accounts_root=accounts_root,
        owner=owner,
    )
    acquire_email_for_register.last_lease = lease  # type: ignore[attr-defined]
    return lease.email, lease.anonymous_id, lease.source

def commit_registration(
    *,
    email: str = "",
    lease_id: str = "",
    cookies_raw: str = "",
    platform: str = DEFAULT_PLATFORM,
    cloud_mark: bool = True,
    inventory_path: str = "",
    coordination_mode: str = "local_fast",
    timeout: float = 25.0,
    log_callback: LogFn = None,
    anonymous_id: str = "",
    label: str = "chatgpt",
) -> None:
    cookies_raw = str(cookies_raw or "").strip()
    if not cookies_raw:
        if log_callback:
            log_callback("[!] commit_registration: 缺少 icloud_cookies，跳过云标记")
        return
    service = alias_pool.get_lease_service(
        cookies_raw,
        inventory_path=inventory_path or alias_pool.DEFAULT_INVENTORY_FILE,
        platform=platform,
        label=label or platform,
        cloud_mark=cloud_mark,
        coordination_mode=coordination_mode,
        timeout=timeout,
    )
    email_n = _norm_email(email)
    if email_n and anonymous_id:
        _email_anon_cache[email_n] = str(anonymous_id)
    service.commit(lease_id=lease_id, email=email_n, log_callback=log_callback)

def release_registration(
    *,
    email: str = "",
    lease_id: str = "",
    cookies_raw: str = "",
    platform: str = DEFAULT_PLATFORM,
    cloud_mark: bool = True,
    inventory_path: str = "",
    coordination_mode: str = "local_fast",
    timeout: float = 25.0,
    recycle: bool = True,
    cooldown: bool = True,
    cooldown_sec: Optional[float] = None,
    reason: str = "",
    log_callback: LogFn = None,
    label: str = "chatgpt",
) -> None:
    cookies_raw = str(cookies_raw or "").strip()
    if not cookies_raw:
        return
    service = alias_pool.get_lease_service(
        cookies_raw,
        inventory_path=inventory_path or alias_pool.DEFAULT_INVENTORY_FILE,
        platform=platform,
        label=label or platform,
        cloud_mark=cloud_mark,
        coordination_mode=coordination_mode,
        timeout=timeout,
        fail_cooldown_sec=float(cooldown_sec or alias_pool.DEFAULT_FAIL_COOLDOWN_SEC),
    )
    service.release(
        lease_id=lease_id,
        email=_norm_email(email),
        recycle=recycle,
        cooldown=cooldown,
        cooldown_sec=cooldown_sec,
        reason=reason,
        log_callback=log_callback,
    )

def check_health(
    *,
    cookies_raw: str = "",
    temp_mail_base: str = "",
    temp_mail_password: str = "",
    temp_mail_custom_auth: str = "",
    used_file: str = "",
    platform: str = DEFAULT_PLATFORM,
    use_local_used: bool = False,
    timeout: float = 15.0,
    http_get: Optional[HttpGet] = None,
) -> Tuple[bool, str]:
    parts = []
    cookies_raw = str(cookies_raw or "").strip()
    if not cookies_raw:
        return False, "未配置 icloud_cookies"
    try:
        aliases = list_aliases(cookies_raw, timeout=timeout, active_only=False)
        plat = str(platform or DEFAULT_PLATFORM).strip().lower() or DEFAULT_PLATFORM
        active = [a for a in aliases if a.get("is_active")]
        cloud_marked = sum(1 for a in active if note_tags.note_has_platform(a.get("note"), plat))
        available = [a for a in active if not note_tags.note_has_platform(a.get("note"), plat)]
        parts.append(
            f"HME OK total={len(aliases)} active={len(active)} "
            f"note含{plat}={cloud_marked} available={len(available)}"
        )
        try:
            inv = alias_pool.get_lease_service(
                cookies_raw,
                inventory_path=alias_pool.DEFAULT_INVENTORY_FILE,
                platform=plat,
                cloud_mark=True,
            ).stats()
            parts.append(
                f"inventory free={inv.get('free')} leased={inv.get('leased')} registered={inv.get('registered')}"
            )
        except Exception:
            pass
        hme_ok = True
    except Exception as exc:
        return False, f"HME cookies 无效/过期: {exc}"

    base = str(temp_mail_base or "").rstrip("/")
    password = str(temp_mail_password or "").strip()
    if not base or not password:
        return False, "; ".join(parts) + "; 未配置 temp_mail base/password"

    if http_get is None:
        parts.append("temp_mail 配置存在(未探测HTTP)")
        return True, "; ".join(parts)

    parts.append(f"temp_mail configured base={base}")
    return True, "; ".join(parts)

def _sleep(seconds: float, cancel_callback: CancelCb = None) -> None:
    end = time.time() + max(float(seconds or 0), 0.0)
    while time.time() < end:
        if cancel_callback and cancel_callback():
            return
        time.sleep(min(0.25, end - time.time()))


def wait_for_verification_code(
    alias_email: str,
    *,
    temp_mail_base: str = "",
    temp_mail_password: str = "",
    temp_mail_target: str = "",
    temp_mail_custom_auth: str = "",
    http_get: Optional[HttpGet] = None,
    timeout: int = 180,
    poll_interval: float = 3.0,
    log_callback: LogFn = None,
    cancel_callback: CancelCb = None,
    exclude_codes: Optional[Set[str]] = None,
    otp_sent_at: Optional[float] = None,
    cookies_raw: str = "",
    inventory_path: str = "",
    platform: str = DEFAULT_PLATFORM,
) -> str:
    """OTP wait is handled by ICloudMailProvider / mail_provider.wait_for_code."""
    _ = (
        alias_email,
        temp_mail_base,
        temp_mail_password,
        temp_mail_target,
        temp_mail_custom_auth,
        http_get,
        timeout,
        poll_interval,
        log_callback,
        cancel_callback,
        exclude_codes,
        otp_sent_at,
        cookies_raw,
        inventory_path,
        platform,
    )
    raise RuntimeError(
        "wait_for_verification_code 请改用 chatgpt2api 的 ICloudMailProvider / mail_provider.wait_for_code"
    )
