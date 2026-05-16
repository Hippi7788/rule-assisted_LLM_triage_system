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
SIGNAL_MAP["auth_flip"] = 10
STATIC_EXT = {".js",".css",".png",".jpg",".jpeg",".gif",".svg",".ico",".woff",".woff2",".map"}

def is_noise(url):
    if not url:
        return True
    path = urlparse(url.lower()).path
    return any(path.endswith(ext) for ext in STATIC_EXT)

def normalize(req):
    url = req.get("url", "/")
    p = urlparse(url)
    path = p.path or "/"

    path = re.sub(r"/[0-9a-fA-F-]{8,}", "/{id}", path)
    path = re.sub(r"/\d+", "/{id}", path)

    headers = str(req.get("headers", "")).lower()
    has_token = bool(req.get("token")) or any(x in headers for x in ["authorization", "bearer", "cookie"])

    return {
        "method": req.get("method", "GET").upper(),
        "path": path,
        "status": int(req.get("status", 0)),
        "has_token": has_token,
        "query": p.query.lower() if p.query else ""
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
        if is_noise(r.get("url")):
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

        final = (base * 0.8 + signal_score * 0.2)
        final *= (0.75 + confidence * 0.5)

        results.append({
            "score": round(final, 2),
            "method": method,
            "path": path,
            "signals": signals,
            "confidence": confidence
        })

    return sorted(results, key=lambda x: x["score"], reverse=True)
