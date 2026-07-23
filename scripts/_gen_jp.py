from pathlib import Path
src = Path(r"G:\project\chatgpt2api\scripts\register_one_2925_113_nodes.py")
text = src.read_text(encoding="utf-8")
# simplify candidates preference: only JP nodes with 0.1
old = '''def pick_candidates(all_nodes: list[str], current: str) -> list[str]:
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
    return out'''
new = '''def pick_candidates(all_nodes: list[str], current: str) -> list[str]:
    # Prefer Japan 0.1x nodes that previously passed CF probe.
    out = [n for n in all_nodes if ("日本东京" in n or "日本" in n) and ("0.1" in n or "H2" in n or "家宽" in n)]
    # unique preserve order
    seen = set()
    ordered = []
    for n in out:
        if n not in seen:
            seen.add(n)
            ordered.append(n)
    if not ordered:
        ordered = [n for n in all_nodes if "日本" in n][:8]
    return ordered[:8]'''
if old not in text:
    raise SystemExit('old block not found')
text = text.replace(old, new)
text = text.replace("p['fixed_prefix_enabled'] = True", "p['fixed_prefix_enabled'] = False")
text = text.replace("p['fixed_prefix'] = p.get('fixed_prefix') or 'fa'", "p['fixed_prefix'] = ''")
text = text.replace("OUT = Path(r'G:\\project\\chatgpt2api\\data\\register_lurenjia113_result.json')", "OUT = Path(r'G:\\project\\chatgpt2api\\data\\register_lurenjia113_result.json')")
text = text.replace("LOG = Path(r'G:\\project\\chatgpt2api\\data\\register_lurenjia113_run3.log')", "LOG = Path(r'G:\\project\\chatgpt2api\\data\\register_lurenjia113_run4.log')")
# ensure LOG path is run4
text = text.replace("register_lurenjia113_run3.log", "register_lurenjia113_run4.log")
# force real t for all flows
needle = "prefer_node=True if force_real_t else None"
# already patched in function patch - check if patch_force exists; nodes script may not force all flows
if "patch_force_real_t" not in text:
    # inject stronger force in prepare by monkeypatch after imports usage in main
    text = text.replace(
        "prepare_config()\n",
        "prepare_config()\n    # force real sentinel t for every flow\n    import services.register.openai_register as _reg\n    _orig = _reg.build_sentinel_token\n    def _wrap(session, device_id, flow, *, page_url='', require_real_t=None):\n        return _orig(session, device_id, flow, page_url=page_url, require_real_t=True)\n    _reg.build_sentinel_token = _wrap\n"
    )
dst = Path(r"G:\project\chatgpt2api\scripts\register_one_2925_113_jp.py")
dst.write_text(text, encoding="utf-8")
print("wrote", dst, "bytes", dst.stat().st_size)
print("fixed_prefix_enabled False?", "fixed_prefix_enabled'] = False" in text)
print("run4?", "run4.log" in text)
print("jp pick?", "日本东京" in text)