import re
from urllib.parse import urlparse
from collections import defaultdict
from llm import ask_llm

STATIC_EXT = {".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".map"}

def is_noise(url: str) -> bool:
    if not url: 
        return True
    path = urlparse(url.lower()).path
    
    if any(path.endswith(ext) for ext in STATIC_EXT):
        if not any(x in path for x in ["/api", "/v", "/graphql", "doc", "swagger"]):
            return True
    return False

def normalize_and_extract(req: dict) -> dict:
    url = req.get("url", "/")
    parsed = urlparse(url)
    path = parsed.path if parsed.path else "/"
    uuid_pattern = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    path = re.sub(f"/{uuid_pattern}", "/{uuid}", path)
    path = re.sub(r"/[0-9a-fA-F]{32}", "/{hash}", path)
    path = re.sub(r"/\d+", "/{id}", path)
    headers = str(req.get("headers", "")).lower()
    has_token = bool(req.get("token")) or any(x in headers for x in ["authorization", "bearer", "cookie"])

    param_count = len([p for p in parsed.query.split("&") if p]) if parsed.query else 0

    return {
        "method": str(req.get("method", "GET")).upper(),
        "path": path,
        "status": int(req.get("status", 0)),
        "has_token": has_token,
        "param_count": param_count
    }

def heuristic(req):
    score = 0
    path = req["path"].lower()

    if req["has_token"]: 
        score += 5
    if "/api" in path: 
        score += 5

    if any(x in path for x in ["/admin", "/user", "/account", "/profile"]):
        score += 8

    if req["status"] in (401, 403): 
        score += 8
    elif req["status"] == 500: 
        score += 5

    if req["param_count"] > 2: 
        score += 3
        
    return score

SIGNAL_MAP = {
    "idor_signal": 20,
    "auth_anomaly": 10,
    "status_inconsistency": 8,
    "safe": 0
}

def process_requests(requests_data):
    grouped = defaultdict(list)
    results = []

    for r in requests_data:
        if is_noise(r.get("url", "")):
            continue
        
        cleaned = normalize_and_extract(r)
        key = f"{cleaned['method']}:{cleaned['path']}"
        grouped[key].append(cleaned)

    for key, req_list in grouped.items():
        method, path = key.split(":", 1)
        base = max(heuristic(r) for r in req_list)
        status_set = set(r["status"] for r in req_list)
        if len(status_set) > 1:
            base += 5

        if base < 5 and len(req_list) == 1:
            continue

        llm = ask_llm(req_list, method, path)

        signals = llm.get("signals") or ["safe"]

        if not any(x in path.lower() for x in ["/user/", "/file/", "/order/", "/account/"]):
            if "idor_signal" in signals:
                signals = [s for s in signals if s != "idor_signal"]

        signal_score = sum(SIGNAL_MAP.get(s, 0) for s in signals)

        try:
            confidence = float(llm.get("confidence", 0.5))
        except (ValueError, TypeError):
            confidence = 0.5
        confidence = max(0.0, min(1.0, confidence))

        base_weight = 0.8
        signal_weight = 0.2
        
        final_score = (base * base_weight) + (signal_score * signal_weight)
        final_score *= (0.5 + confidence)

        results.append({
            "score": round(final_score, 2),
            "method": method,
            "path": path,
            "signals": signals,
            "confidence": confidence
        })

    # 由高到低排序輸出
    return sorted(results, key=lambda x: x["score"], reverse=True)
