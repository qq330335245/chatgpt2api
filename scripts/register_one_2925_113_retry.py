from __future__ import annotations
import json, sys, time, traceback
from datetime import datetime
from pathlib import Path
sys.path.insert(0, r'G:\project\chatgpt2api')
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass
from services.register.openai_register import PlatformRegistrar, config
from services.account_service import account_service
OUT = Path(r'G:\project\chatgpt2api\data\register_lurenjia113_result.json')
mail = config.setdefault('mail', {})
for p in mail.setdefault('providers', []):
    if p.get('type') == 'mail_2925':
        p['enable'] = True
        p['main_email'] = 'lurenjia113@2925.com'
        p['main_password'] = p.get('main_password') or 'aa5601282'
    else:
        p['enable'] = False
proxies = []
if str(config.get('proxy') or '').strip():
    proxies.append(str(config.get('proxy')).strip())
if 'http://192.168.15.144:7890' not in proxies:
    proxies.append('http://192.168.15.144:7890')
proxies.append('')
last_err = None
for attempt, proxy in enumerate(proxies, 1):
    print('attempt', attempt, 'proxy=', proxy or 'NONE', flush=True)
    config['proxy'] = proxy
    registrar = PlatformRegistrar(proxy)
    try:
        try:
            registrar.session.get('https://auth.openai.com/', headers=registrar._navigate_headers(''), timeout=30, allow_redirects=True, verify=False)
            registrar.session.get('https://platform.openai.com/', headers=registrar._navigate_headers(''), timeout=30, allow_redirects=True, verify=False)
            print('warmup_ok', flush=True)
        except Exception as e:
            print('warmup_warn', e, flush=True)
        result = registrar.register(attempt)
        print('SUCCESS', result.get('email'), flush=True)
        try:
            account_service.add_account_items([{**result, 'mail_provider_type': 'mail_2925', 'mail_inbox': 'lurenjia113@2925.com'}])
        except Exception as e:
            print('import_warn', e, flush=True)
        payload = {'ok': True, 'attempt': attempt, 'proxy': proxy, 'main_email': 'lurenjia113@2925.com', 'result': result, 'finished_at': datetime.now().isoformat()}
        OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        cpa = {'type': 'codex', 'email': result.get('email'), 'account_id': '', 'access_token': result.get('access_token'), 'refresh_token': result.get('refresh_token'), 'id_token': result.get('id_token'), 'password': result.get('password'), 'disabled': False}
        cpa_path = Path(r'G:\project\chatgpt2api\data') / ('register_' + str(result.get('email')) + '.json')
        cpa_path.write_text(json.dumps(cpa, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print('EMAIL', result.get('email'), flush=True)
        print('PASSWORD', result.get('password'), flush=True)
        print('CPA', cpa_path, flush=True)
        registrar.close()
        raise SystemExit(0)
    except SystemExit:
        raise
    except Exception as e:
        last_err = e
        print('FAIL', e, flush=True)
        traceback.print_exc()
        registrar.close()
        time.sleep(2)
payload = {'ok': False, 'main_email': 'lurenjia113@2925.com', 'error': str(last_err), 'finished_at': datetime.now().isoformat()}
OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print('ALL_FAILED', last_err, flush=True)
raise SystemExit(1)
