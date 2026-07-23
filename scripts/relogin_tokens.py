#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Batch re-login via JSON account list; output ChatGPT web session credentials.

Usage:
  python scripts/relogin_tokens.py --accounts accounts.json --out-dir data/relogin_out
  python scripts/relogin_tokens.py --accounts accounts.json --mail-config mail.json --concurrency 2

accounts.json:
{
  "defaults": {"mail": {"provider": "cf_temp_mail"}},
  "accounts": [
    {"email": "a@b.com", "password": "", "mail": {"provider": "mail_2925"}},
    {"email": "hme@privaterelay.appleid.com", "mail": {"provider": "icloud", "inbox": "me@icloud.com"}}
  ]
}
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def _load_json(path: Path) -> dict | list:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _iso_from_exp(exp) -> str:
    try:
        ts = int(exp)
        return datetime.fromtimestamp(ts, tz=timezone.utc).astimezone().isoformat()
    except Exception:
        return ""


def _normalize_accounts(raw: dict | list) -> tuple[list[dict], dict]:
    if isinstance(raw, list):
        return [dict(x) for x in raw if isinstance(x, dict)], {}
    if not isinstance(raw, dict):
        raise ValueError("accounts JSON 顶层必须是对象或数组")
    defaults = dict(raw.get("defaults") or {})
    accounts = raw.get("accounts") or raw.get("items") or []
    if not isinstance(accounts, list):
        raise ValueError("accounts 必须是数组")
    return [dict(x) for x in accounts if isinstance(x, dict)], defaults


def _to_output(result: dict) -> dict:
    access = str(result.get("access_token") or "")
    return {
        "type": "chatgpt_session" if result.get("session_token") or result.get("source_type") == "chatgpt_session" else "oauth",
        "email": str(result.get("email") or ""),
        "account_id": str(result.get("account_id") or ""),
        "access_token": access,
        "refresh_token": str(result.get("refresh_token") or ""),
        "id_token": str(result.get("id_token") or ""),
        "session_token": str(result.get("session_token") or ""),
        "expired": _iso_from_exp(result.get("expires_at")),
        "last_refresh": datetime.now().astimezone().isoformat(),
        "source_type": str(result.get("source_type") or ""),
        "disabled": False,
    }


def process_one(
    account: dict,
    *,
    defaults: dict,
    mail_gateway,
    import_pool: bool,
) -> dict:
    from services.account_service import account_service
    from services.register.mail_gateway import AccountMailSpec

    email = str(account.get("email") or account.get("login_email") or "").strip()
    if not email:
        return {"email": "", "ok": False, "error": "missing_email"}

    password = str(account.get("password") or "").strip()
    mail_defaults = defaults.get("mail") if isinstance(defaults.get("mail"), dict) else defaults
    spec = AccountMailSpec.from_account(account, defaults=mail_defaults)

    # bind mail fields for account_service OTP path
    receive_email = spec.inbox
    mail_provider_type = spec.provider
    mail_provider_ref = spec.provider_ref

    started = time.time()
    print(f"[start] {email} provider={spec.provider or '-'} mode={spec.mode}", flush=True)
    try:
        # pre-resolve mailbox (fail fast on mail config)
        handle = mail_gateway.resolve(email, spec)
        print(
            f"[mail] {email} -> provider={handle.provider} inbox={handle.inbox_email} filter={handle.filter_email}",
            flush=True,
        )

        if password:
            result = account_service._login_with_password(
                email,
                password,
                receive_email=receive_email or handle.inbox_email,
                mail_provider_ref=mail_provider_ref or handle.provider_ref,
                mail_provider_type=mail_provider_type or handle.provider,
            )
        else:
            result = account_service._login_with_email_otp(
                email,
                receive_email=receive_email or handle.inbox_email,
                mail_provider_ref=mail_provider_ref or handle.provider_ref,
                mail_provider_type=mail_provider_type or handle.provider,
            )

        elapsed = round(time.time() - started, 2)
        if not result.get("ok"):
            print(f"[fail] {email} {elapsed}s error={result.get('error')}", flush=True)
            return {
                "email": email,
                "ok": False,
                "elapsed": elapsed,
                "error": result.get("error"),
                "detail": result.get("detail"),
            }

        item = _to_output(result)
        if import_pool:
            try:
                account_service.add_account_items(
                    [
                        {
                            **item,
                            "password": password,
                            "mail_inbox": handle.inbox_email,
                            "mail_provider_type": handle.provider,
                            "mail_provider_ref": handle.provider_ref,
                            "source_type": item.get("source_type") or "relogin_script",
                        }
                    ]
                )
            except Exception as exc:
                print(f"[warn] import pool failed {email}: {exc}", flush=True)

        print(
            f"[ok] {email} {elapsed}s account_id={item.get('account_id') or '-'} "
            f"session_token={'yes' if item.get('session_token') else 'no'}",
            flush=True,
        )
        return {"email": email, "ok": True, "elapsed": elapsed, "item": item}
    except Exception as exc:
        elapsed = round(time.time() - started, 2)
        print(f"[exc] {email} {elapsed}s {exc}", flush=True)
        traceback.print_exc()
        return {"email": email, "ok": False, "elapsed": elapsed, "error": str(exc)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="批量重新登录并导出 ChatGPT session 凭证")
    parser.add_argument("--accounts", required=True, type=Path, help="账号 JSON 文件")
    parser.add_argument("--out-dir", type=Path, default=None, help="输出目录，默认 data/relogin_out")
    parser.add_argument("--mail-config", type=Path, default=None, help="可选 mail providers JSON 覆盖")
    parser.add_argument("--concurrency", type=int, default=1, help="并发数，默认 1")
    parser.add_argument("--import-pool", action="store_true", help="成功后写入 chatgpt2api 号池")
    parser.add_argument("--limit", type=int, default=0, help="只处理前 N 个账号，0=全部")
    parser.add_argument("--skip-existing", action="store_true", help="输出文件已存在则跳过")
    args = parser.parse_args(argv)

    accounts_path = args.accounts.expanduser().resolve()
    if not accounts_path.is_file():
        print(f"错误：找不到账号文件 {accounts_path}", file=sys.stderr)
        return 1

    raw = _load_json(accounts_path)
    accounts, defaults = _normalize_accounts(raw)
    if args.limit and args.limit > 0:
        accounts = accounts[: args.limit]
    if not accounts:
        print("错误：账号列表为空", file=sys.stderr)
        return 1

    from services.register.mail_gateway import MailGateway

    override = None
    if args.mail_config:
        mc = _load_json(args.mail_config.expanduser().resolve())
        if isinstance(mc, dict):
            override = mc.get("mail") if isinstance(mc.get("mail"), dict) else mc
    gateway = MailGateway.from_register_json(override=override)

    out_dir = (args.out_dir or (ROOT / "data" / "relogin_out")).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"accounts={len(accounts)} concurrency={args.concurrency} out={out_dir}", flush=True)

    results: list[dict] = []
    pending = []
    for acc in accounts:
        email = str(acc.get("email") or "").strip()
        if not email:
            continue
        out_path = out_dir / f"{email}.json"
        if args.skip_existing and out_path.exists():
            print(f"[skip] {email}", flush=True)
            results.append({"email": email, "ok": True, "skipped": True})
            continue
        pending.append(acc)

    def _run(acc: dict) -> dict:
        r = process_one(
            acc,
            defaults=defaults,
            mail_gateway=gateway,
            import_pool=bool(args.import_pool),
        )
        if r.get("ok") and r.get("item") and not r.get("skipped"):
            email = r["email"]
            out_path = out_dir / f"{email}.json"
            out_path.write_text(
                json.dumps(r["item"], ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            r["path"] = str(out_path)
        return r

    if args.concurrency <= 1:
        for acc in pending:
            results.append(_run(acc))
    else:
        with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as pool:
            futs = [pool.submit(_run, acc) for acc in pending]
            for fut in as_completed(futs):
                results.append(fut.result())

    ok = sum(1 for r in results if r.get("ok"))
    fail = len(results) - ok
    summary = {
        "total": len(results),
        "ok": ok,
        "fail": fail,
        "finished_at": datetime.now().isoformat(),
        "results": [
            {
                "email": r.get("email"),
                "ok": r.get("ok"),
                "error": r.get("error"),
                "path": r.get("path"),
                "elapsed": r.get("elapsed"),
                "skipped": r.get("skipped"),
            }
            for r in results
        ],
    }
    (out_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"done ok={ok} fail={fail} summary={out_dir / 'summary.json'}", flush=True)
    return 0 if fail == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())