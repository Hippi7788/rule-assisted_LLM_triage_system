from filter import filter_request
from llm import ask_llm

def heuristic_score(req: dict) -> int:
    score = 0
    path = req["path"].lower()

    if req["has_token"]:
        score += 8
    if "/api" in path:
        score += 6
        
    if any(x in path for x in ["/admin", "/user", "/account", "/setting", "/profile"]):
        score += 8

    high_risk_actions = ["delete", "upload", "download", "export", "config", "debug", "graphql", "v1/internal"]
    if any(action in path for action in high_risk_actions):
        score += 10

    if req["status"] in (403, 401):
        score += 8
    elif req["status"] == 500:
        score += 8

    if req["param_count"] > 3:
        score += 4

    return score

def process_requests(requests_data: list) -> list:
    results = []
    seen_endpoints = set()

    for req in requests_data:
        cleaned = filter_request(req)
        if not cleaned:
            continue

        fingerprint = f"{cleaned['method']}:{cleaned['path']}:{cleaned['status']}"
        if fingerprint in seen_endpoints:
            continue
        
        base = heuristic_score(cleaned)

        if base < 5: 
            continue

        seen_endpoints.add(fingerprint)

        llm_result = ask_llm(cleaned)
        llm_score = llm_result.get("score", 0)

        final_score = llm_score + (base * 0.3)

        results.append({
            "score": round(final_score, 2),
            "path": cleaned["path"],
            "method": cleaned["method"],
            "status": cleaned["status"],
            "tags": llm_result.get("tags", []),
            "reason": llm_result.get("reason", "")
        })

    return sorted(results, key=lambda x: x["score"], reverse=True)
