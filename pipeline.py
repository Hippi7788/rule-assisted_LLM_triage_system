import re
from urllib.parse import urlparse
from collections import defaultdict
from llm import ask_llm

STATIC_EXT = {".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".map"}

def is_noise(url: str) -> bool:
    if not url: return True
    path = urlparse(url.lower()).path
    if any(path.endswith(ext) for ext in STATIC_EXT):
        if not any(x in path for x in ["/api", "/v", "/graphql", "doc", "swagger"]):
            return True
    return False

def normalize_and_extract(req: dict) -> dict:
    url = req.get("url", "/")
    parsed = urlparse(url)
    path = parsed.path if parsed.path else "/"
    raw_path_last_segment = path.split("/")[-1] if "/" in path else ""

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
        "param_count": param_count,
        "raw_segment": raw_path_last_segment,
        "raw_url": url
    }

def heuristic(req):
    score = 0
    path = req["path"].lower()
    if req["has_token"]: score += 5
    if "/api" in path: score += 5
    if any(x in path for x in ["/admin", "/user", "/account", "/profile"]): score += 8
    if req["status"] in (401, 403): score += 8
    elif req["status"] == 500: score += 5
    if req["param_count"] > 2: score += 3
    return score

SIGNAL_MAP = {
    "auth_bypass_hint": 25,
    "unauthorized_access_observed": 20,
    "object_access_variance": 15,
    "auth_state_flip": 10,
    "safe": 0
}

def process_requests(requests_data):
    grouped = defaultdict(list)
    results = []

    for r in requests_data:
        if is_noise(r.get("url", "")): continue
        cleaned = normalize_and_extract(r)
        key = f"{cleaned['method']}:{cleaned['path']}"
        grouped[key].append(cleaned)

    for key, req_list in grouped.items():
        method, path = key.split(":", 1)
        base = max(heuristic(r) for r in req_list)
        status_set = set(r["status"] for r in req_list)
        auth_set = set(r["has_token"] for r in req_list)
        segment_set = set(r["raw_segment"] for r in req_list)

        has_status_variance = len(status_set) > 1
        has_auth_variance = len(auth_set) > 1
        has_object_variance = len(segment_set) > 1 and ("{id}" in path or "{uuid}" in path or "{hash}" in path)

        if has_status_variance: base += 4
        if has_auth_variance: base += 4
        if has_object_variance: base += 6 

        if base < 5 and len(req_list) == 1:
            continue

        llm = ask_llm(req_list, method, path)
        signals = llm.get("signals") or ["safe"]

        if not is_idor_candidate_path := any(x in path.lower() for x in ["/user/", "/file/", "/order/", "/account/"]):
            signals = [s for s in signals if s != "object_access_variance"]

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

    return sorted(results, key=lambda x: x["score"], reverse=True)
