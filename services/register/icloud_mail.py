# -*- coding: utf-8 -*-
"""iCloud Hide My Email provider for chatgpt2api register/relogin.

Ported from grokRegister-cpa:
  - lease/create HME aliases via Apple cookies + local SQLite inventory
  - platform note tags for multi-app coordination
  - OTP via IMAP shared mailbox or Cloudflare temp-mail forward (X-ICLOUD-HME)

Modes:
  - imap: read shared iCloud IMAP, filter by Hide My Email alias
  - temp_mail / hme: lease aliases and read OTP from CF/other forward inbox
"""

from __future__ import annotations

import email as email_lib
import imaplib
import re
from email.header import decode_header, make_header
from email.utils import parsedate_to_datetime
from html import unescape
from typing import Any

from services.register import icloud as icloud_service
from services.register import icloud_pool as alias_pool
from services.register.mail_provider import BaseMailProvider

ICLOUD_IMAP_HOST = "imap.mail.me.com"
ICLOUD_IMAP_PORT = 993
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
HME_HEADER_RE = re.compile(
    r"(?im)^X-ICLOUD-HME\s*:\s*(.+?)(?:\r?\n(?![ \t])|\Z)"
)
HME_P_RE = re.compile(r"(?i)\bp\s*=\s*([^;]+)")


def _decode_header_value(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return str(value)


def _html_to_text(html: str) -> str:
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", html or "")
    text = re.sub(r"(?is)<br\s*/?>", "\n", text)
    text = re.sub(r"(?is)</p>", "\n", text)
    text = re.sub(r"(?is)<.*?>", " ", text)
    return unescape(re.sub(r"[ \t]+", " ", text)).strip()


def _truthy(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if not text:
        return default
    if text in {"1", "true", "yes", "on", "y"}:
        return True
    if text in {"0", "false", "no", "off", "n"}:
        return False
    return default


def _as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except Exception:
        return float(default)


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def extract_x_icloud_hme_alias(raw_or_mail: Any) -> str:
    """Extract Hide My Email alias from Apple X-ICLOUD-HME header / raw mail."""
    if isinstance(raw_or_mail, dict):
        raw = str(
            raw_or_mail.get("raw")
            or raw_or_mail.get("source")
            or raw_or_mail.get("text")
            or raw_or_mail.get("text_content")
            or ""
        )
        # already-normalized fields
        for key in ("hme", "hme_alias", "filter_email", "alias"):
            value = str(raw_or_mail.get(key) or "").strip().lower()
            if value and "@" in value:
                return value
    else:
        raw = str(raw_or_mail or "")

    if not raw:
        return ""

    match = HME_HEADER_RE.search(raw)
    header = match.group(1).strip() if match else ""
    if not header:
        # fallback: anywhere in blob
        loose = re.search(r"(?i)X-ICLOUD-HME\s*[:=]\s*([^\r\n]+)", raw)
        header = loose.group(1).strip() if loose else ""
    if not header:
        return ""

    p_match = HME_P_RE.search(header)
    candidate = (p_match.group(1) if p_match else header).strip().strip("\"'")
    # header may still contain angle-addr noise
    email_match = EMAIL_RE.search(candidate)
    return (email_match.group(0) if email_match else candidate).strip().lower()


def mail_targets_hme_alias(mail: dict[str, Any] | str, alias_email: str) -> bool:
    """True if this mail's X-ICLOUD-HME p= equals the alias (preferred), else To/body fallback."""
    target = str(alias_email or "").strip().lower()
    if not target:
        return True
    found = extract_x_icloud_hme_alias(mail)
    if found:
        return found == target
    if isinstance(mail, dict):
        blob = "\n".join(
            str(mail.get(key) or "")
            for key in (
                "to",
                "subject",
                "text",
                "text_content",
                "html",
                "html_content",
                "raw",
                "source",
            )
        ).lower()
    else:
        blob = str(mail or "").lower()
    if target in blob:
        return True
    return target in {m.lower() for m in EMAIL_RE.findall(blob)}


class ICloudMailProvider(BaseMailProvider):
    name = "icloud"

    def __init__(self, entry: dict, conf: dict):
        super().__init__(conf, str(entry.get("provider_ref") or ""))
        self.entry = dict(entry or {})
        self.mail_config_full = entry.get("_mail_config") if isinstance(entry.get("_mail_config"), dict) else None

        mode = str(
            entry.get("connection_mode") or entry.get("mode") or entry.get("receive_mode") or ""
        ).strip().lower()
        # HME lease path is the default when cookies are present.
        cookies = str(
            entry.get("icloud_cookies")
            or entry.get("cookies")
            or entry.get("account_cookies")
            or ""
        ).strip()
        if mode in {"temp_mail", "cf", "forward", "hme", "hide_my_email", "alias"}:
            self.connection_mode = "temp_mail"
        elif mode in {"imap", "shared_imap", "alias_imap"}:
            self.connection_mode = "imap"
        elif cookies:
            self.connection_mode = "temp_mail"
        else:
            self.connection_mode = "imap"

        self.cookies_raw = cookies
        self.shared_email = str(
            entry.get("shared_email")
            or entry.get("main_email")
            or entry.get("email")
            or ""
        ).strip().lower()
        self.shared_password = str(
            entry.get("shared_password")
            or entry.get("main_password")
            or entry.get("password")
            or entry.get("app_password")
            or ""
        ).strip()
        self.imap_host = str(entry.get("imap_host") or ICLOUD_IMAP_HOST).strip() or ICLOUD_IMAP_HOST
        self.imap_port = _as_int(entry.get("imap_port"), ICLOUD_IMAP_PORT)
        self.timeout = _as_float(
            entry.get("timeout") or conf.get("request_timeout") or 30,
            30.0,
        )

        # temp_mail / HME forward target
        self.temp_mail_type = str(
            entry.get("temp_mail_type") or entry.get("forward_provider") or "cloudflare_temp_email"
        ).strip()
        self.temp_mail_ref = str(
            entry.get("temp_mail_provider_ref") or entry.get("temp_mail_ref") or ""
        ).strip()
        self.temp_mail_target = str(
            entry.get("temp_mail_target_email")
            or entry.get("temp_mail_target")
            or entry.get("target_email")
            or entry.get("inbox")
            or entry.get("inbox_address")
            or ""
        ).strip().lower()

        # lease / inventory knobs (grokRegister-cpa compatible names)
        self.platform = str(
            entry.get("platform")
            or entry.get("icloud_platform_tag")
            or entry.get("platform_tag")
            or "chatgpt"
        ).strip().lower() or "chatgpt"
        self.label = str(
            entry.get("label")
            or entry.get("icloud_alias_label")
            or self.platform
            or "chatgpt"
        ).strip() or "chatgpt"
        self.inventory_path = str(
            entry.get("inventory_path")
            or entry.get("icloud_inventory_file")
            or entry.get("inventory_file")
            or alias_pool.DEFAULT_INVENTORY_FILE
        ).strip()
        self.reuse_aliases = _truthy(entry.get("reuse_aliases", entry.get("icloud_reuse_aliases", True)), True)
        self.create_when_exhausted = _truthy(
            entry.get("create_when_exhausted", entry.get("icloud_create_when_exhausted", True)),
            True,
        )
        self.cloud_mark = _truthy(entry.get("cloud_mark", entry.get("icloud_cloud_mark", True)), True)
        self.coordination_mode = str(
            entry.get("coordination_mode") or entry.get("icloud_coordination_mode") or "local_fast"
        ).strip().lower() or "local_fast"
        self.async_mark = _truthy(entry.get("async_mark", entry.get("icloud_async_mark", True)), True)
        self.background_replenish = _truthy(
            entry.get("background_replenish", entry.get("icloud_background_replenish", True)),
            True,
        )
        self.low_watermark = _as_int(entry.get("low_watermark", entry.get("icloud_low_watermark")), alias_pool.DEFAULT_LOW_WATERMARK)
        self.high_watermark = _as_int(entry.get("high_watermark", entry.get("icloud_high_watermark")), alias_pool.DEFAULT_HIGH_WATERMARK)
        self.replenish_interval_sec = _as_float(
            entry.get("replenish_interval_sec", entry.get("icloud_replenish_interval_sec")),
            alias_pool.DEFAULT_REPLENISH_INTERVAL_SEC,
        )
        self.create_per_cycle = _as_int(
            entry.get("create_per_cycle", entry.get("icloud_create_per_cycle")),
            alias_pool.DEFAULT_CREATE_PER_CYCLE,
        )
        self.lease_ttl_sec = _as_float(
            entry.get("lease_ttl_sec", entry.get("icloud_lease_ttl_sec")),
            alias_pool.DEFAULT_LEASE_TTL_SEC,
        )
        self.sync_interval_sec = _as_float(
            entry.get("sync_interval_sec", entry.get("icloud_sync_interval_sec")),
            alias_pool.DEFAULT_SYNC_INTERVAL_SEC,
        )
        self.fail_cooldown_sec = _as_float(
            entry.get("fail_cooldown_sec", entry.get("icloud_fail_cooldown_sec")),
            alias_pool.DEFAULT_FAIL_COOLDOWN_SEC,
        )
        self.fail_cooldown_max_sec = _as_float(
            entry.get("fail_cooldown_max_sec", entry.get("icloud_fail_cooldown_max_sec")),
            alias_pool.DEFAULT_FAIL_COOLDOWN_MAX_SEC,
        )
        self.fail_cooldown_threshold = _as_int(
            entry.get("fail_cooldown_threshold", entry.get("icloud_fail_cooldown_threshold")),
            alias_pool.DEFAULT_FAIL_COOLDOWN_THRESHOLD,
        )
        self.hme_timeout = _as_float(entry.get("hme_timeout") or entry.get("apple_timeout") or 25, 25.0)

        if self.connection_mode == "imap":
            if not self.shared_email or not self.shared_password:
                raise RuntimeError("icloud IMAP 模式需要 shared_email + shared_password(app password)")
        else:
            # HME create path needs cookies; pure forward read can work without cookies
            pass

    # ------------------------------------------------------------------ helpers
    def _full_mail_config(self) -> dict[str, Any]:
        if isinstance(self.mail_config_full, dict):
            return self.mail_config_full
        conf = self.conf if isinstance(self.conf, dict) else {}
        return {"providers": [], **conf}

    def _lease_kwargs(self) -> dict[str, Any]:
        return {
            "inventory_path": self.inventory_path,
            "reuse_aliases": self.reuse_aliases,
            "create_when_exhausted": self.create_when_exhausted,
            "label": self.label,
            "platform": self.platform,
            "cloud_mark": self.cloud_mark,
            "coordination_mode": self.coordination_mode,
            "async_mark": self.async_mark,
            "background_replenish": self.background_replenish,
            "low_watermark": self.low_watermark,
            "high_watermark": self.high_watermark,
            "replenish_interval_sec": self.replenish_interval_sec,
            "create_per_cycle": self.create_per_cycle,
            "fail_cooldown_sec": self.fail_cooldown_sec,
            "fail_cooldown_max_sec": self.fail_cooldown_max_sec,
            "fail_cooldown_threshold": self.fail_cooldown_threshold,
            "lease_ttl_sec": self.lease_ttl_sec,
            "sync_interval_sec": self.sync_interval_sec,
            "timeout": self.hme_timeout,
        }

    def _mailbox_from_alias(
        self,
        alias: str,
        *,
        anonymous_id: str = "",
        lease_id: str = "",
        source: str = "",
        receive_email: str = "",
    ) -> dict[str, Any]:
        alias_n = str(alias or "").strip().lower()
        if not alias_n:
            raise RuntimeError("icloud 邮箱地址不能为空")

        if self.connection_mode == "temp_mail":
            from services.register import mail_provider as mp

            inbox = str(receive_email or self.temp_mail_target or "").strip()
            cfg = self._full_mail_config()
            try:
                mailbox = mp.get_existing_mailbox(
                    cfg,
                    alias_n,
                    receive_email=inbox,
                    provider_ref=self.temp_mail_ref,
                    provider_type=self.temp_mail_type or "cloudflare_temp_email",
                )
            except Exception:
                # CF optional at create-time; still return a usable handle and let wait path retry.
                mailbox = {
                    "provider": self.temp_mail_type or "cloudflare_temp_email",
                    "provider_ref": self.temp_mail_ref,
                    "address": alias_n,
                    "filter_email": alias_n,
                    "inbox_address": inbox or alias_n,
                    "auth_mode": "admin",
                    "token": "forward",
                }
            mailbox = dict(mailbox)
            mailbox["provider"] = self.name
            mailbox["provider_ref"] = self.provider_ref
            mailbox["address"] = alias_n
            mailbox["filter_email"] = alias_n
            mailbox["auth_mode"] = mailbox.get("auth_mode") or "admin"
            mailbox.setdefault("token", mailbox.get("token") or "forward")
            if inbox:
                mailbox["inbox_address"] = inbox
            mailbox["icloud_mode"] = "temp_mail"
        else:
            mailbox = {
                "provider": self.name,
                "provider_ref": self.provider_ref,
                "address": alias_n,
                "filter_email": alias_n,
                "inbox_address": self.shared_email,
                "auth_mode": "admin",
                "token": "imap",
                "shared_email": self.shared_email,
                "icloud_mode": "imap",
            }

        if anonymous_id:
            mailbox["icloud_anonymous_id"] = str(anonymous_id)
        if lease_id:
            mailbox["icloud_lease_id"] = str(lease_id)
        if source:
            mailbox["icloud_source"] = str(source)
        if self.cookies_raw:
            mailbox["icloud_cookies"] = self.cookies_raw
        mailbox["icloud_platform"] = self.platform
        mailbox["icloud_inventory_path"] = self.inventory_path
        mailbox["icloud_label"] = self.label
        mailbox["label"] = f"iCloud HME/{self.platform}"
        return mailbox

    # ------------------------------------------------------------------ BaseMailProvider
    def create_mailbox(self, username: str | None = None) -> dict[str, Any]:
        """Acquire a Hide My Email alias for registration.

        username, when provided and looks like an email, reuses that alias (relogin/debug).
        Otherwise lease/create via inventory pool (requires icloud_cookies).
        """
        hint = str(username or "").strip().lower()
        if hint and "@" in hint:
            return self.get_existing_mailbox(hint)

        if not self.cookies_raw:
            raise RuntimeError(
                "icloud create_mailbox 需要 icloud_cookies（Apple 网页登录 Cookie），"
                "用于 Hide My Email 租约/创建；或传入已有 alias email"
            )

        lease = icloud_service.acquire_lease(
            self.cookies_raw,
            owner=f"chatgpt2api:{self.provider_ref or self.name}",
            **self._lease_kwargs(),
        )
        return self._mailbox_from_alias(
            lease.email,
            anonymous_id=lease.anonymous_id,
            lease_id=lease.lease_id,
            source=lease.source,
        )

    def get_existing_mailbox(self, email: str, receive_email: str = "") -> dict[str, Any]:
        alias = str(email or "").strip().lower()
        if not alias:
            raise RuntimeError("icloud 邮箱地址不能为空")
        return self._mailbox_from_alias(alias, receive_email=receive_email)

    def mark_result(self, mailbox: dict[str, Any], *, success: bool, error: Exception | str | None = None) -> None:
        """Commit lease on success; recycle/cooldown on failure."""
        if not self.cookies_raw and not str((mailbox or {}).get("icloud_cookies") or "").strip():
            return
        cookies = str((mailbox or {}).get("icloud_cookies") or self.cookies_raw or "").strip()
        email = str((mailbox or {}).get("address") or (mailbox or {}).get("filter_email") or "").strip()
        lease_id = str((mailbox or {}).get("icloud_lease_id") or "").strip()
        anonymous_id = str((mailbox or {}).get("icloud_anonymous_id") or "").strip()
        inventory_path = str((mailbox or {}).get("icloud_inventory_path") or self.inventory_path or "")
        platform = str((mailbox or {}).get("icloud_platform") or self.platform or "chatgpt")
        if success:
            try:
                icloud_service.commit_registration(
                    email=email,
                    lease_id=lease_id,
                    cookies_raw=cookies,
                    platform=platform,
                    cloud_mark=self.cloud_mark,
                    inventory_path=inventory_path,
                    coordination_mode=self.coordination_mode,
                    timeout=self.hme_timeout,
                    anonymous_id=anonymous_id,
                    label=self.label,
                )
            except Exception:
                # registration already succeeded; inventory mark is best-effort
                pass
            return

        reason = str(error or "")[:200]
        try:
            icloud_service.release_registration(
                email=email,
                lease_id=lease_id,
                cookies_raw=cookies,
                platform=platform,
                cloud_mark=self.cloud_mark,
                inventory_path=inventory_path,
                coordination_mode=self.coordination_mode,
                timeout=self.hme_timeout,
                recycle=True,
                cooldown=True,
                reason=reason,
                label=self.label,
            )
        except Exception:
            pass

    def release(self, mailbox: dict[str, Any]) -> None:
        """Release an unused lease without permanent register mark."""
        self.mark_result(mailbox, success=False, error="released")

    # ------------------------------------------------------------------ IMAP / nested fetch
    def _connect(self):
        return imaplib.IMAP4_SSL(self.imap_host, self.imap_port, timeout=self.timeout)

    def _close(self, conn) -> None:
        if not conn:
            return
        try:
            conn.close()
        except Exception:
            pass
        try:
            conn.logout()
        except Exception:
            pass

    def _parse_message(self, raw: bytes, msg_id: bytes | str) -> dict[str, Any]:
        msg = email_lib.message_from_bytes(raw)
        subject = _decode_header_value(msg.get("Subject"))
        sender = _decode_header_value(msg.get("From"))
        recipients: list[str] = []
        for header in ("To", "Delivered-To", "X-Original-To", "Cc"):
            value = _decode_header_value(msg.get(header))
            if value:
                recipients.append(value)
        hme_header = _decode_header_value(msg.get("X-ICLOUD-HME"))
        bodies: list[str] = []
        if msg.is_multipart():
            for part in msg.walk():
                ctype = (part.get_content_type() or "").lower()
                if ctype not in {"text/plain", "text/html"}:
                    continue
                try:
                    payload = part.get_payload(decode=True) or b""
                    charset = part.get_content_charset() or "utf-8"
                    text = payload.decode(charset, errors="replace")
                except Exception:
                    continue
                if ctype == "text/html":
                    text = _html_to_text(text)
                if text.strip():
                    bodies.append(text)
        else:
            try:
                payload = msg.get_payload(decode=True) or b""
                charset = msg.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace")
                if (msg.get_content_type() or "").lower() == "text/html":
                    text = _html_to_text(text)
                bodies.append(text)
            except Exception:
                bodies.append("")
        body = "\n".join(bodies)
        received_at = None
        try:
            if msg.get("Date"):
                received_at = parsedate_to_datetime(msg.get("Date"))
        except Exception:
            received_at = None
        mid = str(msg_id.decode("ascii", errors="ignore") if isinstance(msg_id, bytes) else msg_id)
        message_id = str(msg.get("Message-ID") or msg.get("Message-Id") or "").strip()
        if message_id:
            mid = f"{mid}:{message_id}"
        raw_text = ""
        try:
            raw_text = raw.decode("utf-8", errors="replace")
        except Exception:
            raw_text = body
        hme_alias = extract_x_icloud_hme_alias(hme_header) or extract_x_icloud_hme_alias(raw_text)
        return {
            "id": mid,
            "message_id": mid,
            "subject": subject,
            "from": sender,
            "sender": sender,
            "to": " ".join(recipients),
            "text": body,
            "text_content": body,
            "html": body,
            "html_content": body,
            "received_at": received_at,
            "raw": raw_text,
            "hme_alias": hme_alias,
            "provider": self.name,
            "mailbox": hme_alias or " ".join(recipients),
        }

    def _message_targets_alias(self, message: dict[str, Any], alias: str) -> bool:
        return mail_targets_hme_alias(message, alias)

    def fetch_latest_message(self, mailbox: dict[str, Any]) -> dict[str, Any] | None:
        mode = str(mailbox.get("icloud_mode") or self.connection_mode or "").strip().lower()
        if mode in {"temp_mail", "cf", "forward", "hme"}:
            from services.register import mail_provider as mp

            cfg = self._full_mail_config()
            handle = mp.get_existing_mailbox(
                cfg,
                str(mailbox.get("filter_email") or mailbox.get("address") or ""),
                receive_email=str(
                    mailbox.get("inbox_address") or self.temp_mail_target or ""
                ),
                provider_ref=self.temp_mail_ref,
                provider_type=self.temp_mail_type or "cloudflare_temp_email",
            )
            provider = mp._create_provider(
                cfg,
                str(handle.get("provider") or self.temp_mail_type),
                str(handle.get("provider_ref") or self.temp_mail_ref),
            )
            try:
                if hasattr(provider, "fetch_latest_message"):
                    message = provider.fetch_latest_message(handle)
                    if not message:
                        return None
                    # Prefer strict HME header match when raw is present.
                    alias = str(mailbox.get("filter_email") or mailbox.get("address") or "").strip().lower()
                    raw_item = message.get("raw") if isinstance(message.get("raw"), dict) else message
                    if alias and not mail_targets_hme_alias(raw_item, alias):
                        # nested CF matcher may have used loose body match; accept only if header absent
                        if extract_x_icloud_hme_alias(raw_item):
                            return None
                    return message
            finally:
                provider.close()
            return None

        alias = str(mailbox.get("filter_email") or mailbox.get("address") or "").strip().lower()
        conn = None
        try:
            conn = self._connect()
            typ, _ = conn.login(self.shared_email, self.shared_password)
            if typ != "OK":
                raise RuntimeError(f"icloud IMAP 登录失败: {typ}")
            typ, data = conn.select("INBOX", readonly=True)
            if typ != "OK":
                raise RuntimeError("icloud IMAP select INBOX 失败")
            try:
                count = int(data[0]) if data and data[0] else 0
            except Exception:
                count = 0
            if count <= 0:
                return None
            start = max(1, count - 19)
            ids = [str(i).encode("ascii") for i in range(count, start - 1, -1)]
            for msg_id in ids:
                typ, fetch_data = conn.fetch(msg_id, "(RFC822)")
                if typ != "OK" or not fetch_data:
                    continue
                raw = b""
                for part in fetch_data:
                    if isinstance(part, tuple) and len(part) > 1:
                        raw = part[1]
                        break
                if not raw:
                    continue
                message = self._parse_message(raw, msg_id)
                if self._message_targets_alias(message, alias):
                    return message
            return None
        finally:
            self._close(conn)
