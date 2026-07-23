from __future__ import annotations

import json
import sys
import time
import traceback
import urllib.parse
from datetime import datetime
from pathlib import Path

import requests

sys.path.insert(0, r"G:\project\chatgpt2api")
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from services.register.openai_register import PlatformRegistrar, config, build_sentinel_token
from services.account_service import account_service

ROOT = Path(r"G:\project\chatgpt2api")
OUT = ROOT / "data" / "register_lurenjia113_result.json"
LOG = ROOT / "data" / "register_lurenjia113_run3.log"
MAIN_EMAIL = "lurenjia113@2925.com"
PROXY = "http://192.168.15.144:7890"
MIHOMO = "http://192.168.15.144:9090"
MIHOMO_SECRET = "123456"
GROUP = "OpenAI"


def log(msg: str) -> None:
    line = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def mihomo_headers() -> dict:
    return {"Authorization": f"Bearer {MIHOMO_SECRET}", "Content-Type": "application/json"}


def get_openai_nodes() -> tuple[str, list[str]]:
    r = requests.get(f"{MIHOMO}/proxies/{urllib.parse.quote(GROUP)}", headers=mihomo_headers(), timeout=15)
    r.raise_for_status()
    data = r.json()
    return str(data.get("now") or ""), list(data.get("all") or [])


def switch_node(name: str) -> None:
    r = requests.put(
        f"{MIHOMO}/proxies/{urllib.parse.quote(GROUP)}",
        headers=mihomo_headers(),
        json={"name": name},
        timeout=15,
    )
    if r.status_code not in (200, 204):
        raise RuntimeError(f"switch_failed_{r.status_code}:{r.text[:200]}")


def exit_ip() -> str:
    try:
        r = requests.get("https://api.ipify.org?format=json", proxies={"http": PROXY, "https": PROXY}, timeout=20)
        return str(r.json().get("ip") or "")
    except Exception as e:
        return f"err:{e}"


def pick_candidates(all_nodes: list[str], current: str) -> list[str]:
    preferred_keywords = ["家宽", "H2", "原生", "美国", "日本", "德国", "台湾", "新加坡", "香港", "加拿大", "英国", "韩国"]
    deprioritize = ["剩余流量", "套餐到期", "官网", "DIRECT", "REJECT", "以下为"]
    ranked: list[tuple[int, str]] = []
    for n in all_nodes:
        if any(x in n for x in deprioritize):
            continue
        score = 0
        for i, kw in enumerate(preferred_keywords):
            if kw in n:
                score += 100 - i
        if "AWS" in n:
            score -= 20
        if "0.1倍" in n or "0.01倍" in n:
            score += 5
        if n == current:
            score -= 50
        ranked.append((score, n))
    ranked.sort(key=lambda x: (-x[0], x[1]))
    # keep unique top nodes
    out = []
    for _, n in ranked:
        if n not in out:
            out.append(n)
        if len(out) >= 12:
            break
    if current and current not in out:
        out.insert(0, current)
    return out


def prepare_config() -> None:
    mail = config.setdefault("mail", {})
    for p in mail.setdefault("providers", []):
        if p.get("type") == "mail_2925":
            p["enable"] = True
            p["main_email"] = MAIN_EMAIL
            p["main_password"] = p.get("main_password") or "aa5601282"
            p["fixed_prefix_enabled"] = True
            p["fixed_prefix"] = p.get("fixed_prefix") or "fa"
            p["alias_length"] = int(p.get("alias_length") or 4)
        else:
            p["enable"] = False
    config["proxy"] = PROXY


def patch_force_real_t() -> None:
    # force real sentinel `t` for register/create flows
    import services.register.openai_register as reg

    orig = reg.build_sentinel_token

    def wrapped(session, device_id, flow, *, page_url="", require_real_t=None):
        force = require_real_t
        if force is None and str(flow or "") in {
            "username_password_create",
            "email_otp_send",
            "email_otp_verify",
            "oauth_create_account",
            "authorize_continue",
        }:
            force = True
        return orig(session, device_id, flow, page_url=page_url, require_real_t=force)

    reg.build_sentinel_token = wrapped


def main() -> int:
    LOG.write_text("", encoding="utf-8")
    prepare_config()
    patch_force_real_t()

    current, all_nodes = get_openai_nodes()
    candidates = pick_candidates(all_nodes, current)
    log(f"current_openai_node={current}")
    log(f"candidates={len(candidates)}")
    for i, n in enumerate(candidates, 1):
        log(f"  {i}. {n}")

    last_err = None
    for attempt, node in enumerate(candidates, 1):
        try:
            switch_node(node)
            time.sleep(1.2)
            ip = exit_ip()
            log(f"attempt {attempt}/{len(candidates)} node={node} ip={ip}")
        except Exception as e:
            log(f"attempt {attempt} switch_warn={e}")
            ip = "unknown"

        config["proxy"] = PROXY
        registrar = PlatformRegistrar(PROXY)
        try:
            try:
                registrar.session.get(
                    "https://auth.openai.com/",
                    headers=registrar._navigate_headers(""),
                    timeout=30,
                    allow_redirects=True,
                    verify=False,
                )
                registrar.session.get(
                    "https://platform.openai.com/",
                    headers=registrar._navigate_headers(""),
                    timeout=30,
                    allow_redirects=True,
                    verify=False,
                )
                log("warmup_ok")
            except Exception as e:
                log(f"warmup_warn {e}")

            result = registrar.register(attempt)
            log(f"SUCCESS email={result.get('email')}")
            try:
                account_service.add_account_items(
                    [{**result, "mail_provider_type": "mail_2925", "mail_inbox": MAIN_EMAIL}]
                )
            except Exception as e:
                log(f"import_warn {e}")

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
            cpa_path = ROOT / "data" / f"register_{result.get('email')}.json"
            cpa_path.write_text(json.dumps(cpa, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

            payload = {
                "ok": True,
                "attempt": attempt,
                "node": node,
                "exit_ip": ip,
                "main_email": MAIN_EMAIL,
                "result": result,
                "cpa_path": str(cpa_path),
                "finished_at": datetime.now().isoformat(),
            }
            OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            log(f"EMAIL {result.get('email')}")
            log(f"PASSWORD {result.get('password')}")
            log(f"CPA {cpa_path}")
            registrar.close()
            return 0
        except Exception as e:
            last_err = e
            log(f"FAIL {e}")
            traceback.print_exc()
            registrar.close()
            time.sleep(2.5)

    payload = {
        "ok": False,
        "main_email": MAIN_EMAIL,
        "error": str(last_err),
        "finished_at": datetime.now().isoformat(),
    }
    OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    log(f"ALL_FAILED {last_err}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
