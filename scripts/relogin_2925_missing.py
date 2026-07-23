from __future__ import annotations

import json
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(r"G:\project\chatgpt2api")
sys.path.insert(0, str(ROOT))

# force utf-8 stdout on Windows
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from services.account_service import account_service  # noqa: E402

EMAILS_FILE = Path(r"C:\Users\qq333\Documents\Codex\2026-07-22\new-chat-3\work\2925_missing_from_cpa.txt")
OUT_DIR = ROOT / "data" / "2925_missing_relogin"
SUMMARY_PATH = OUT_DIR / "summary.json"
WORKERS = 1
LIMIT = 0


def _iso_from_exp(exp) -> str:
    try:
        ts = int(exp)
        return datetime.fromtimestamp(ts, tz=timezone.utc).astimezone().isoformat()
    except Exception:
        return ""


def to_cpa_json(result: dict) -> dict:
    access = str(result.get("access_token") or "")
    payload = account_service._decode_jwt_payload(access) if access else {}
    return {
        "type": "codex",
        "email": str(result.get("email") or ""),
        "account_id": str(result.get("account_id") or ""),
        "access_token": access,
        "refresh_token": str(result.get("refresh_token") or ""),
        "id_token": str(result.get("id_token") or ""),
        "expired": _iso_from_exp(result.get("expires_at") or payload.get("exp")),
        "last_refresh": _iso_from_exp(payload.get("iat")),
        "disabled": False,
    }


def process_one(email: str) -> dict:
    email = email.strip().lower().lstrip("\ufeff")
    started = time.time()
    print(f"[start] {email}", flush=True)
    try:
        result = account_service._login_with_email_otp(
            email,
            receive_email="",
            mail_provider_ref="",
            mail_provider_type="mail_2925",
        )
        elapsed = round(time.time() - started, 2)
        if result.get("ok"):
            item = to_cpa_json(result)
            out_path = OUT_DIR / f"{email}.json"
            out_path.write_text(json.dumps(item, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            try:
                account_service.add_account_items(
                    [
                        {
                            "access_token": item["access_token"],
                            "refresh_token": item["refresh_token"],
                            "id_token": item["id_token"],
                            "email": item["email"],
                            "account_id": item["account_id"],
                            "source_type": "email_otp",
                            "mail_provider_type": "mail_2925",
                            "password": "",
                        }
                    ]
                )
            except Exception as exc:
                print(f"[warn] import account failed {email}: {exc}", flush=True)
            print(f"[ok] {email} {elapsed}s", flush=True)
            return {"email": email, "ok": True, "elapsed": elapsed, "path": str(out_path)}
        print(f"[fail] {email} {elapsed}s error={result.get('error')}", flush=True)
        return {
            "email": email,
            "ok": False,
            "elapsed": elapsed,
            "error": result.get("error"),
            "detail": result.get("detail"),
        }
    except Exception as exc:
        elapsed = round(time.time() - started, 2)
        print(f"[exc] {email} {elapsed}s {exc}", flush=True)
        traceback.print_exc()
        return {"email": email, "ok": False, "elapsed": elapsed, "error": str(exc)}


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    raw = EMAILS_FILE.read_text(encoding="utf-8-sig")
    emails = [line.strip().lstrip("\ufeff") for line in raw.splitlines() if line.strip()]
    if LIMIT > 0:
        emails = emails[:LIMIT]
    print(f"total={len(emails)} workers={WORKERS} out={OUT_DIR}", flush=True)

    pending = []
    skipped = []
    for email in emails:
        path = OUT_DIR / f"{email}.json"
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if data.get("access_token") and data.get("refresh_token"):
                    skipped.append(email)
                    continue
            except Exception:
                pass
        pending.append(email)
    print(f"pending={len(pending)} skipped_existing={len(skipped)}", flush=True)

    results = []
    if WORKERS <= 1:
        for email in pending:
            results.append(process_one(email))
    else:
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            futs = {pool.submit(process_one, email): email for email in pending}
            for fut in as_completed(futs):
                results.append(fut.result())

    ok = sum(1 for r in results if r.get("ok"))
    fail = len(results) - ok
    # strip heavy detail for summary size
    light = []
    for r in results:
        item = {k: v for k, v in r.items() if k != "detail"}
        if not r.get("ok"):
            detail = r.get("detail") if isinstance(r.get("detail"), dict) else {}
            item["page_type"] = str(detail.get("page_type") or "")
            item["error"] = r.get("error")
        light.append(item)
    summary = {
        "finished_at": datetime.now().isoformat(),
        "total": len(emails),
        "pending": len(pending),
        "skipped_existing": len(skipped),
        "ok": ok,
        "fail": fail,
        "results": light,
    }
    SUMMARY_PATH.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"DONE ok={ok} fail={fail} summary={SUMMARY_PATH}", flush=True)
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
