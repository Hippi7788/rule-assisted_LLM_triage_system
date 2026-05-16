import json
import re
from urllib.parse import urlparse
from collections import defaultdict
from llm import ask_llm

try:
    with open("owasp_knowledge.json", "r", encoding="utf-8") as f:
        OWASP = json.load(f)
except:
    OWASP = {}

SIGNAL_MAP = {}
OWASP_INDEX = {}
for v in OWASP.values():
    if isinstance(v, dict):
        sig_name = v.get("signal")
        if sig_name:
            SIGNAL_MAP[sig_name] = v.get("weight", 0)
            OWASP_INDEX[sig_name] = v

SIGNAL_MAP["safe"] = 0
SIGNAL_MAP["auth_state_flip"] = 10

STATIC_EXT = {".js",".css",".png",".jpg",".jpeg",".gif",".svg",".ico",".woff",".woff2",".map"}

def is_noise(url):
    if not url:
        return True

    url_str = str(url).lower()
    path = urlparse(url_str).path if "://" in url_str else url_str.split("?")[0]
    return any(path.endswith(ext) for ext in STATIC_EXT)

def fuzzy_find_token(obj) -> str:
    """
    核心黑科技：全物件深度優先模糊搜尋 (Fuzzy Flatten Scan)
    不論 Token 叫什麼名字、埋在多深的巢狀 JSON/Headers 裡，都能自動掘出並分類身分
    """

    obj_str = str(obj).lower()
    if not any(x in obj_str for x in ["token", "auth", "bearer", "cookie", "jwt", "session"]):
        return "none"

    if isinstance(obj, dict):
        for k, v in obj.items():
            k_low = str(k).lower()
            if any(x in k_low for x in ["token", "auth", "cookie", "session", "jwt", "secret"]):
                if v and isinstance(v, (str, int)):
                    v_str = str(v).lower()
                    if "admin" in v_str: return "admin"
                    if "user" in v_str: return "user"
                    return "present"

            if isinstance(v, (dict, list)):
                res = fuzzy_find_token(v)
                if res != "none": return res

    elif isinstance(obj, list):
        for item in obj:
            item_str = str(item).lower()
            if any(x in item_str for x in ["authorization", "bearer", "cookie:", "token"]):
                if "admin" in item_str: return "admin"
                return "user" if "user" in item_str else "present"
            if isinstance(item, (dict, list)):
                res = fuzzy_find_token(item)
                if res != "none": return res

    return "none"

def normalize(req):
    url = req.get("url") or req.get("path") or "/"
    url_str = str(url)
    p = urlparse(url_str) if "://" in url_str else None
    
    path = p.path if p else url_str.split("?")[0]
    query = p.query.lower() if p else (url_str.split("?")[1].lower() if "?" in url_str else "")

    path = re.sub(r"/[0-9a-fA-F-]{8,}", "/{id}", path)
    path = re.sub(r"/\d+", "/{id}", path)

    token_label = fuzzy_find_token(req)
    has_token = (token_label != "none")

    return {
        "method": str(req.get("method", "GET")).upper(),
        "path": path,
        "status": int(req.get("status", req.get("responseStatus", 0))), 
        "has_token": has_token,
        "token_label": token_label,
        "query": query
    }

def heuristic(r):
    s = 0
    if r["has_token"]: s += 5
    if "/api" in r["path"]: s += 5
    if r["status"] in (401,403): s += 8
    if r["status"] == 500: s += 5
    return s

def apply_guardrails(signals, method, path, query):
    path_l = path.lower()
    q = query.lower()

    filtered = []

    for s in signals:
        if s == "safe":
            filtered.append("safe")
            continue

        if s == "auth_state_flip":
            filtered.append(s)
            continue

        rule = OWASP_INDEX.get(s)
        if not rule:
            continue

        if s == "rce_file_upload_hint" and method not in ("POST", "PUT"):
            continue

        has_path_match = any(k in path_l for k in rule.get("path_keywords", []))
        has_param_match = any(k in q for k in rule.get("param_keywords", []))

        if not (has_path_match or has_param_match):
            continue

        filtered.append(s)

    if len(filtered) > 1 and "safe" in filtered:
        filtered = [f for f in filtered if f != "safe"]

    return filtered or ["safe"]

def process_requests(data):
    groups = defaultdict(list)
    results = []

    for r in data:
        if is_noise(r.get("url") or r.get("path")):
            continue
        
        c = normalize(r)
        key = f"{c['method']}:{c['path']}"
        groups[key].append(c)

    for key, reqs in groups.items():
        method, path = key.split(":", 1)

        base = max(heuristic(r) for r in reqs)

        status_set = set(r["status"] for r in reqs)
        if len(status_set) > 1:
            base += 5

        if len(reqs) == 1 and base < 5:
            continue

        llm = ask_llm(reqs, method, path)
        signals = llm.get("signals") or ["safe"]
        query = " ".join(r["query"] for r in reqs)
        signals = apply_guardrails(signals, method, path, query)
        signal_score = sum(SIGNAL_MAP.get(s, 0) for s in signals)

        try:
            confidence = float(llm.get("confidence", 0.5))
        except (ValueError, TypeError):
            confidence = 0.5
        confidence = max(0.0, min(1.0, confidence))

        final = (base * 0.8 + signal_score * 0.2) * (0.75 + confidence * 0.5)

        results.append({
            "score": round(final, 2),
            "method": method,
            "path": path,
            "signals": signals,
            "confidence": confidence
        })

    return sorted(results, key=lambda x: x["score"], reverse=True)
