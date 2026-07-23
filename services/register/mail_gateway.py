# -*- coding: utf-8 -*-
"""Unified mail OTP gateway for register/relogin scripts.

Maps account-level mail specs onto existing mail_provider backends:

  direct     - login email is the inbox (CF address, some 2925 aliases)
  catch_all  - login email is alias; physical inbox is another mailbox (CF)
  alias_imap - login email is alias; read main IMAP and filter (2925/iCloud)

Account mail field examples:
  {"provider": "mail_2925"}
  {"provider": "cf_temp_mail", "mode": "catch_all", "inbox": "catch@x.com"}
  {"provider": "icloud", "inbox": "me@icloud.com"}  # filter defaults to email
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from services.register import mail_provider


@dataclass
class AccountMailSpec:
    """Per-account mail routing for OTP."""

    provider: str = ""
    provider_ref: str = ""
    mode: str = ""  # direct | catch_all | alias_imap | ""
    inbox: str = ""
    filter_to: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_account(cls, account: dict[str, Any], defaults: dict[str, Any] | None = None) -> "AccountMailSpec":
        defaults = dict(defaults or {})
        mail = account.get("mail") if isinstance(account.get("mail"), dict) else {}
        mail = {**defaults, **mail}
        # flat fallbacks
        provider = str(
            mail.get("provider")
            or mail.get("type")
            or account.get("mail_provider_type")
            or defaults.get("provider")
            or ""
        ).strip()
        provider_ref = str(
            mail.get("provider_ref")
            or mail.get("ref")
            or account.get("mail_provider_ref")
            or ""
        ).strip()
        inbox = str(
            mail.get("inbox")
            or mail.get("receive_email")
            or mail.get("inbox_email")
            or account.get("mail_inbox")
            or account.get("receive_email")
            or ""
        ).strip()
        filter_to = str(
            mail.get("filter_to")
            or mail.get("filter_email")
            or account.get("email")
            or ""
        ).strip()
        mode = str(mail.get("mode") or "").strip().lower()
        if not mode:
            if provider in {"mail_2925", "icloud"}:
                mode = "alias_imap"
            elif inbox and filter_to and inbox.lower() != filter_to.lower():
                mode = "catch_all"
            else:
                mode = "direct"
        extra = {
            k: v
            for k, v in mail.items()
            if k
            not in {
                "provider",
                "type",
                "provider_ref",
                "ref",
                "mode",
                "inbox",
                "receive_email",
                "inbox_email",
                "filter_to",
                "filter_email",
            }
        }
        return cls(
            provider=provider,
            provider_ref=provider_ref,
            mode=mode,
            inbox=inbox,
            filter_to=filter_to,
            extra=extra,
        )


@dataclass
class MailboxHandle:
    login_email: str
    provider: str
    provider_ref: str
    inbox_email: str
    filter_email: str
    mode: str
    mailbox: dict[str, Any]
    mail_config: dict[str, Any]


class MailGateway:
    """Resolve per-account mail specs and wait for OTP codes."""

    def __init__(self, mail_config: dict[str, Any] | None = None):
        self.mail_config = dict(mail_config or {})
        # ensure defaults
        self.mail_config.setdefault("wait_timeout", 90)
        self.mail_config.setdefault("wait_interval", 2)
        self.mail_config.setdefault("request_timeout", 30)
        self.mail_config.setdefault("providers", [])

    @classmethod
    def from_register_json(cls, path: str | None = None, *, override: dict | None = None) -> "MailGateway":
        from services.config import DATA_DIR
        import json
        from pathlib import Path

        mail: dict[str, Any] = {
            "request_timeout": 30,
            "wait_timeout": 90,
            "wait_interval": 2,
            "providers": [],
            "api_use_register_proxy": True,
        }
        register_proxy = ""
        cfg_path = Path(path) if path else (DATA_DIR / "register.json")
        try:
            raw = json.loads(cfg_path.read_text(encoding="utf-8"))
            if isinstance(raw.get("mail"), dict):
                mail = {**mail, **raw["mail"]}
            register_proxy = str(raw.get("proxy") or "").strip()
        except Exception:
            pass
        if override:
            mail = {**mail, **override}
            if isinstance(override.get("providers"), list):
                mail["providers"] = list(override["providers"])

        use_proxy = True
        flag = mail.get("api_use_register_proxy")
        if isinstance(flag, bool):
            use_proxy = flag
        elif str(flag or "").strip().lower() in {"0", "false", "no", "off"}:
            use_proxy = False
        proxy = register_proxy if use_proxy else ""
        if not proxy:
            try:
                from services.config import config

                proxy = str(config.get_proxy_settings() or "").strip()
            except Exception:
                proxy = ""
        mail["proxy"] = proxy
        return cls(mail)

    def resolve(self, login_email: str, spec: AccountMailSpec | dict | None = None) -> MailboxHandle:
        login_email = str(login_email or "").strip()
        if not login_email:
            raise RuntimeError("login_email 不能为空")
        if isinstance(spec, dict):
            spec = AccountMailSpec.from_account({"email": login_email, "mail": spec})
        elif spec is None:
            spec = AccountMailSpec.from_account({"email": login_email})

        filter_email = str(spec.filter_to or login_email).strip()
        receive_email = ""
        provider_type = str(spec.provider or "").strip()
        provider_ref = str(spec.provider_ref or "").strip()

        # Normalize provider aliases
        aliases = {
            "cf": "cloudflare_temp_email",
            "cf_temp_mail": "cloudflare_temp_email",
            "cloudflare": "cloudflare_temp_email",
            "cloudflare_temp_mail": "cloudflare_temp_email",
            "2925": "mail_2925",
            "mail2925": "mail_2925",
            "icloud_hme": "icloud",
            "apple": "icloud",
        }
        provider_type = aliases.get(provider_type.lower(), provider_type) if provider_type else provider_type

        mode = spec.mode
        if mode == "catch_all":
            receive_email = str(spec.inbox or "").strip()
            if not receive_email:
                raise RuntimeError("catch_all 模式需要 mail.inbox（代收箱地址）")
        elif mode == "alias_imap":
            # inbox optional: provider main/shared mailbox from config
            receive_email = str(spec.inbox or "").strip()
        else:  # direct
            receive_email = str(spec.inbox or "").strip()

        mailbox = mail_provider.get_existing_mailbox(
            self.mail_config,
            login_email,
            receive_email=receive_email,
            provider_ref=provider_ref,
            provider_type=provider_type,
        )
        mailbox["filter_email"] = filter_email
        mailbox.setdefault("address", login_email)
        mailbox["_code_not_before"] = datetime.now(timezone.utc)
        return MailboxHandle(
            login_email=login_email,
            provider=str(mailbox.get("provider") or provider_type or ""),
            provider_ref=str(mailbox.get("provider_ref") or provider_ref or ""),
            inbox_email=str(
                mailbox.get("inbox_address")
                or mailbox.get("inbox")
                or receive_email
                or login_email
            ),
            filter_email=filter_email,
            mode=mode,
            mailbox=mailbox,
            mail_config=self.mail_config,
        )

    def wait_otp(
        self,
        handle: MailboxHandle,
        *,
        timeout: float | None = None,
        interval: float | None = None,
    ) -> str:
        cfg = dict(handle.mail_config)
        if timeout is not None:
            cfg["wait_timeout"] = float(timeout)
        if interval is not None:
            cfg["wait_interval"] = float(interval)
        # ensure boundary not too old
        handle.mailbox.setdefault("_code_not_before", datetime.now(timezone.utc))
        code = mail_provider.wait_for_code(cfg, handle.mailbox)
        if not code:
            raise TimeoutError(
                f"等待验证码超时: login={handle.login_email} "
                f"provider={handle.provider} inbox={handle.inbox_email} "
                f"filter={handle.filter_email}"
            )
        return str(code).strip()