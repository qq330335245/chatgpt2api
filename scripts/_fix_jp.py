from pathlib import Path
p = Path(r"G:\project\chatgpt2api\scripts\register_one_2925_113_jp.py")
t = p.read_text(encoding="utf-8")
t = t.replace('p["fixed_prefix_enabled"] = True', 'p["fixed_prefix_enabled"] = False')
t = t.replace('p["fixed_prefix"] = p.get("fixed_prefix") or "fa"', 'p["fixed_prefix"] = ""')
t = t.replace('p["alias_length"] = int(p.get("alias_length") or 4)', 'p["alias_length"] = 8')
# inject force-real-t if not already
if "_wrap" not in t and "require_real_t=True" not in t:
    t = t.replace(
        "prepare_config()\n",
        "prepare_config()\n    import services.register.openai_register as _reg\n    _orig = _reg.build_sentinel_token\n    def _wrap(session, device_id, flow, *, page_url=\"\", require_real_t=None):\n        return _orig(session, device_id, flow, page_url=page_url, require_real_t=True)\n    _reg.build_sentinel_token = _wrap\n",
    )
p.write_text(t, encoding="utf-8")
for i, ln in enumerate(t.splitlines(), 1):
    if any(k in ln for k in ["fixed_prefix", "alias_length", "_wrap", "require_real_t=True", "日本东京"]):
        print(f"{i}:{ln}")