import json
import time
import urllib.parse
from pathlib import Path

import requests
from curl_cffi import requests as cr

OUT = Path(r"G:\project\chatgpt2api\data\node_probe_auth.jsonl")
LOG = Path(r"G:\project\chatgpt2api\data\node_probe_console.log")
MI = "http://192.168.15.144:9090"
H = {"Authorization": "Bearer 123456", "Content-Type": "application/json"}
proxy = "http://192.168.15.144:7890"
OUT.write_text("", encoding="utf-8")
LOG.write_text("", encoding="utf-8")

def log(msg):
    print(msg, flush=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(msg + "\n")

r = requests.get(MI + "/proxies/" + urllib.parse.quote("OpenAI"), headers=H, timeout=15)
data = r.json()
alln = data.get("all") or []
cands = [n for n in alln if any(k in n for k in ["家宽", "原生", "住宅", "H2", "美国", "日本", "德国"]) and "剩余" not in n][:10]
cands = list(dict.fromkeys([data.get("now")] + cands))
log("cands " + str(len(cands)))
for n in cands:
    if not n:
        continue
    rr = requests.put(MI + "/proxies/" + urllib.parse.quote("OpenAI"), headers=H, json={"name": n}, timeout=15)
    row = {"node": n, "switch": rr.status_code}
    try:
        s = cr.Session(proxies={"http": proxy, "https": proxy}, impersonate="chrome", verify=False, timeout=25)
        resp = s.get("https://auth.openai.com/", allow_redirects=True)
        row.update({
            "status": resp.status_code,
            "cf_ray": resp.headers.get("cf-ray"),
            "challenge": "Just a moment" in (resp.text or ""),
            "len": len(resp.text or ""),
        })
    except Exception as e:
        row["error"] = str(e)
    line = json.dumps(row, ensure_ascii=False)
    log(line)
    with OUT.open("a", encoding="utf-8") as f:
        f.write(line + "\n")
    time.sleep(0.5)
log("DONE")