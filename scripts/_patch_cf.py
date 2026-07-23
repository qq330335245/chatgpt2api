from pathlib import Path
p = Path(r"G:\project\chatgpt2api\scripts\register_control_cf.py")
t = p.read_text(encoding="utf-8")
t = t.replace("register_lurenjia113_result.json", "register_control_cf_result.json")
t = t.replace("lurenjia113@2925.com", "cloudflare_control")
# replace provider enable logic block roughly
old = '''for p in mail.setdefault('providers', []):
    if p.get('type') == 'mail_2925':
        p['enable'] = True
        p['main_email'] = 'cloudflare_control'
        p['main_password'] = p.get('main_password') or 'aa5601282'
    else:
        p['enable'] = False'''
new = '''for p in mail.setdefault('providers', []):
    if p.get('type') == 'cloudflare_temp_email':
        p['enable'] = True
    else:
        p['enable'] = False'''
if old not in t:
    # try double quotes version
    old2 = old.replace("'", '"')
    new2 = new.replace("'", '"')
    if old2 in t:
        t = t.replace(old2, new2)
    else:
        print('BLOCK NOT FOUND')
        # dump relevant lines
        for i, ln in enumerate(t.splitlines(), 1):
            if 'providers' in ln or 'enable' in ln or 'mail_2925' in ln or 'type' in ln:
                print(i, ln)
else:
    t = t.replace(old, new)
# remove mail_inbox hardcode
t = t.replace(", 'mail_provider_type': 'mail_2925', 'mail_inbox': 'cloudflare_control'", "")
t = t.replace(', "mail_provider_type": "mail_2925", "mail_inbox": "cloudflare_control"', "")
p.write_text(t, encoding="utf-8")
print('done', p.stat().st_size)
for i, ln in enumerate(p.read_text(encoding='utf-8').splitlines(), 1):
    if any(k in ln for k in ['enable', 'cloudflare', 'mail_2925', 'OUT', 'main_email']):
        print(f'{i}:{ln}')