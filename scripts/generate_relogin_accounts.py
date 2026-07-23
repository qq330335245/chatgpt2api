#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从邮箱号列表 txt 自动识别类型并生成 relogin accounts.json。

识别规则:
  - 后缀 @2925.com           -> mail_2925 (alias_imap，主箱读信)
  - 后缀 @icloud.com         -> icloud，收件箱固定 apple@konsin.net（CF 代收筛别名）
  - 其余                     -> cf_temp_mail (direct；若域名非 CF 本地邮箱可再改 catch_all)

Usage:
  python scripts/generate_relogin_accounts.py emails.txt -o data/relogin_accounts.json
  python scripts/generate_relogin_accounts.py emails.txt --icloud-inbox apple@konsin.net
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

EMAIL_RE = re.compile(r"^[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}$", re.I)

DEFAULT_ICLOUD_INBOX = "apple@konsin.net"


def _parse_emails(text: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip().lstrip("\ufeff")
        if not line or line.startswith("#"):
            continue
        # support email----password or email,password
        for sep in ("----", ",", "\t", " "):
            if sep in line:
                line = line.split(sep, 1)[0].strip()
                break
        email = line.lower()
        if not EMAIL_RE.match(email):
            continue
        if email in seen:
            continue
        seen.add(email)
        out.append(email)
    return out


def _classify(email: str, *, icloud_inbox: str) -> dict:
    domain = email.rsplit("@", 1)[-1].lower()
    item: dict = {"email": email, "password": ""}

    if domain == "2925.com":
        item["mail"] = {
            "provider": "mail_2925",
            "mode": "alias_imap",
            "filter_to": email,
        }
        return item

    if domain == "icloud.com" or domain.endswith(".icloud.com"):
        # Hide My Email / icloud aliases: 物理收件固定 CF 代收箱
        item["mail"] = {
            "provider": "icloud",
            "mode": "catch_all",  # gateway 会走 receive_email 代收
            "inbox": icloud_inbox,
            "filter_to": email,
            # 兼容 account_service 字段
            "provider_type_hint": "icloud",
        }
        # 同时写平铺字段，方便 relogin_tokens / account_service 直接读
        item["mail_provider_type"] = "icloud"
        item["mail_inbox"] = icloud_inbox
        item["receive_email"] = icloud_inbox
        return item

    # 默认 CF：若就是 CF 域名直收；否则也可当 catch-all 用 inbox
    item["mail"] = {
        "provider": "cf_temp_mail",
        "mode": "direct",
        "filter_to": email,
    }
    item["mail_provider_type"] = "cloudflare_temp_email"
    return item


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="邮箱列表 -> relogin accounts.json")
    parser.add_argument("emails_txt", type=Path, help="邮箱号列表 txt（一行一个）")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="输出 accounts.json（默认与 txt 同目录: <stem>_accounts.json）",
    )
    parser.add_argument(
        "--icloud-inbox",
        default=DEFAULT_ICLOUD_INBOX,
        help=f"iCloud 类账号固定代收箱（默认 {DEFAULT_ICLOUD_INBOX}）",
    )
    parser.add_argument(
        "--default-provider",
        default="cf_temp_mail",
        help="defaults.mail.provider（默认 cf_temp_mail）",
    )
    args = parser.parse_args(argv)

    src = args.emails_txt.expanduser().resolve()
    if not src.is_file():
        print(f"错误：找不到文件 {src}", file=sys.stderr)
        return 1

    emails = _parse_emails(src.read_text(encoding="utf-8-sig"))
    if not emails:
        print("错误：未解析到有效邮箱", file=sys.stderr)
        return 1

    icloud_inbox = str(args.icloud_inbox or DEFAULT_ICLOUD_INBOX).strip()
    accounts = [_classify(e, icloud_inbox=icloud_inbox) for e in emails]

    # stats
    stats = {"mail_2925": 0, "icloud": 0, "cf_temp_mail": 0}
    for a in accounts:
        p = str((a.get("mail") or {}).get("provider") or "")
        if p in stats:
            stats[p] += 1
        elif p == "cloudflare_temp_email":
            stats["cf_temp_mail"] += 1

    payload = {
        "defaults": {
            "mail": {
                "provider": str(args.default_provider or "cf_temp_mail"),
            }
        },
        "accounts": accounts,
        "meta": {
            "source": str(src),
            "total": len(accounts),
            "stats": stats,
            "icloud_inbox": icloud_inbox,
            "rules": {
                "2925.com": "mail_2925",
                "icloud.com": f"icloud catch_all inbox={icloud_inbox}",
                "other": "cf_temp_mail direct",
            },
        },
    }

    out = (
        args.output.expanduser().resolve()
        if args.output
        else src.with_name(f"{src.stem}_accounts.json")
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out}")
    print(f"total={len(accounts)} 2925={stats['mail_2925']} icloud={stats['icloud']} cf={stats['cf_temp_mail']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())