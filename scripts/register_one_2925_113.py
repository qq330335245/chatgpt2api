import json
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, r"G:\project\chatgpt2api")
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from services.register.openai_register import PlatformRegistrar, config
from services.account_service import account_service
from services.register import mail_provider

OUT = Path(r"G:\project\chatgpt2api\data\register_lurenjia113_result.json")

# ensure only 2925 enabled in live config object
mail = config.get("mail") or {}
providers = mail.get("providers") or []
for p in providers:
    if p.get("type") == "mail_2925":
        p["enable"] = True
        p["main_email"] = "lurenjia113@2925.com"
    else:
        p["enable"] = False
mail["providers"] = providers
config["mail"] = mail
print("proxy=", config.get("proxy"), flush=True)
print("providers=", [(p.get("type"), p.get("enable"), p.get("main_email")) for p in providers], flush=True)

# smoke create mailbox first
mb = mail_provider.create_mailbox(mail)
print("sample_mailbox=", mb.get("address"), "provider=", mb.get("provider"), flush=True)

registrar = PlatformRegistrar(config.get("proxy") or "")
started = datetime.now().isoformat()
try:
    print("register_begin", flush=True)
    result = registrar.register(1)
    print("register_ok", result.get("email"), flush=True)
    try:
        account_service.add_account_items([result])
        print("account_imported", flush=True)
    except Exception as e:
        print("account_import_warn", e, flush=True)
    payload = {
        "ok": True,
        "started_at": started,
        "finished_at": datetime.now().isoformat(),
        "main_email": "lurenjia113@2925.com",
        "result": result,
    }
    OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    # also cpa style
    cpa = {
        "type": "codex",
        "email": result.get("email"),
        "account_id": "",
        "access_token": result.get("access_token"),
        "refresh_token": result.get("refresh_token"),
        "id_token": result.get("id_token"),
        "password": result.get("password"),
        "disabled": False,
    }
    email = str(result.get("email") or "unknown")
    cpa_path = Path(r"G:\project\chatgpt2api\data") / f"register_{email}.json"
    cpa_path.write_text(json.dumps(cpa, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("saved", OUT, flush=True)
    print("saved_cpa", cpa_path, flush=True)
    print("EMAIL", email, flush=True)
    print("PASSWORD", result.get("password"), flush=True)
    print("HAS_AT", bool(result.get("access_token")), flush=True)
    print("HAS_RT", bool(result.get("refresh_token")), flush=True)
except Exception as e:
    traceback.print_exc()
    payload = {
        "ok": False,
        "started_at": started,
        "finished_at": datetime.now().isoformat(),
        "main_email": "lurenjia113@2925.com",
        "error": str(e),
    }
    OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("register_fail", e, flush=True)
    raise
finally:
    registrar.close()
