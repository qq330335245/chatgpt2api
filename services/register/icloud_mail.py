# -*- coding: utf-8 -*-
"""iCloud shared-mailbox OTP provider for chatgpt2api register/relogin.

Modes:
  - imap: read shared iCloud IMAP, filter by Hide My Email alias
  - temp_mail: alias forwarded to CF/other temp mail; resolve via nested provider
"""

from __future__ import annotations

import email as email_lib
import imaplib
import re
import time
from email.header import decode_header, make_header
from email.utils import parsedate_to_datetime
from html import unescape
from typing import Any

from services.register.mail_provider import BaseMailProvider, _extract_code

ICLOUD_IMAP_HOST = "imap.mail.me.com"
ICLOUD_IMAP_PORT = 993
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


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


class ICloudMailProvider(BaseMailProvider):
    name = "icloud"

    def __init__(self, entry: dict, conf: dict):
        super().__init__(conf, str(entry.get("provider_ref") or ""))
        self.connection_mode = str(
            entry.get("connection_mode") or entry.get("mode") or "imap"
        ).strip().lower()
        if self.connection_mode in {"temp_mail", "cf", "forward"}:
            self.connection_mode = "temp_mail"
        else:
            self.connection_mode = "imap"

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
        try:
            self.imap_port = int(entry.get("imap_port") or ICLOUD_IMAP_PORT)
        except Exception:
            self.imap_port = ICLOUD_IMAP_PORT
        try:
            self.timeout = float(entry.get("timeout") or conf.get("request_timeout") or 30)
        except Exception:
            self.timeout = 30.0

        # temp_mail forward: use another provider entry type
        self.temp_mail_type = str(
            entry.get("temp_mail_type") or entry.get("forward_provider") or "cloudflare_temp_email"
        ).strip()
        self.temp_mail_ref = str(entry.get("temp_mail_provider_ref") or entry.get("temp_mail_ref") or "").strip()
        self.temp_mail_target = str(
            entry.get("temp_mail_target_email")
            or entry.get("target_email")
            or entry.get("inbox")
            or ""
        ).strip().lower()

        if self.connection_mode == "imap":
            if not self.shared_email or not self.shared_password:
                raise RuntimeError("icloud IMAP 模式需要 shared_email + shared_password(app password)")
        else:
            if not self.temp_mail_target and not self.temp_mail_ref:
                # allow type-only lookup of CF
                pass

    def create_mailbox(self, username: str | None = None) -> dict[str, Any]:
        # re-login uses get_existing_mailbox; create is rare for iCloud aliases
        alias = str(username or "").strip().lower()
        if not alias:
            raise RuntimeError("icloud create_mailbox 需要 alias email")
        return self.get_existing_mailbox(alias)

    def get_existing_mailbox(self, email: str, receive_email: str = "") -> dict[str, Any]:
        alias = str(email or "").strip().lower()
        if not alias:
            raise RuntimeError("icloud 邮箱地址不能为空")
        if self.connection_mode == "temp_mail":
            from services.register import mail_provider as mp

            inbox = str(receive_email or self.temp_mail_target or "").strip()
            # Reuse CF (or configured) backend for catch-all
            cfg = self.mail_config_full or (
                {"providers": [], **(self.conf if isinstance(self.conf, dict) else {})}
            )
            mailbox = mp.get_existing_mailbox(
                cfg,
                alias,
                receive_email=inbox,
                provider_ref=self.temp_mail_ref,
                provider_type=self.temp_mail_type or "cloudflare_temp_email",
            )
            mailbox["provider"] = self.name
            mailbox["provider_ref"] = self.provider_ref
            mailbox["filter_email"] = alias
            mailbox["auth_mode"] = mailbox.get("auth_mode") or "admin"
            mailbox.setdefault("token", mailbox.get("token") or "forward")
            return mailbox

        return {
            "provider": self.name,
            "provider_ref": self.provider_ref,
            "address": alias,
            "filter_email": alias,
            "inbox_address": self.shared_email,
            "auth_mode": "admin",
            "token": "imap",
            "shared_email": self.shared_email,
        }

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
        return {
            "id": mid,
            "subject": subject,
            "from": sender,
            "to": " ".join(recipients),
            "text": body,
            "html": body,
            "received_at": received_at.isoformat() if received_at else "",
        }

    def _message_targets_alias(self, message: dict[str, Any], alias: str) -> bool:
        target = (alias or "").strip().lower()
        if not target:
            return True
        blob = f"{message.get('to') or ''}\n{message.get('subject') or ''}\n{message.get('text') or ''}".lower()
        if target in blob:
            return True
        found = {m.lower() for m in EMAIL_RE.findall(blob)}
        return target in found

    def fetch_latest_message(self, mailbox: dict[str, Any]) -> dict[str, Any] | None:
        if self.connection_mode == "temp_mail":
            # delegate to nested provider via mail_provider wait path:
            # recreate nested mailbox fetch by provider factory
            from services.register import mail_provider as mp

            nested = dict(mailbox)
            # provider field was overridden to icloud; restore nested type for wait
            # Use conf providers: get_existing again and fetch via that provider
            cfg = self.mail_config_full or (
                {"providers": [], **(self.conf if isinstance(self.conf, dict) else {})}
            )
            handle = mp.get_existing_mailbox(
                cfg,
                str(mailbox.get("filter_email") or mailbox.get("address") or ""),
                receive_email=str(mailbox.get("inbox_address") or self.temp_mail_target or ""),
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
                    return provider.fetch_latest_message(handle)
            finally:
                provider.close()
            return None

        alias = str(
            mailbox.get("filter_email") or mailbox.get("address") or ""
        ).strip().lower()
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
            # recent 20
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