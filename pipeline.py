from filter import filter_request
from llm import ask_llm_with_context
from collections import defaultdict

AUTH_ENDPOINTS = ["/login", "/logout", "/signup", "/register"]

def is_auth_endpoint(path: str) -> bool:
    return any(x in path for x in AUTH_ENDPOINTS)

def is_idor_candidate(path: str) -> bool:
    return any(x in path for x in ["/user/", "/file/", "/order/", "/account/"])

def heuristic_score(req: dict) -> int:
    score = 0
    path = req["path"].lower()

    if req["has_token"]:
        score += 8
    if "/api" in path:
        score += 6
        
    if any(x in path for x in ["/admin", "/user", "/account", "/setting", "/profile"]):
        score += 8

    high_risk_actions = ["delete", "upload", "download", "export", "config", "debug", "graphql", "internal"]
    segments = path.split("/")
    if any(action in segments for action in high_risk_actions):
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
    api_groups = defaultdict(list)

    for req in requests_data:
        cleaned = filter_request(req)
        if not cleaned:
            continue
        
        group_key = f"{cleaned['method']}:{cleaned['path']}"
        
        if any(r['status'] == cleaned['status'] and r['has_token'] == cleaned['has_token'] for r in api_groups[group_key]):
            continue
            
        api_groups[group_key].append(cleaned)
        
    for group_key, req_list in api_groups.items():
        method, path = group_key.split(":", 1)
        base = max(heuristic_score(r) for r in req_list)
        status_set = set(r["status"] for r in req_list)
        has_divergence = len(status_set) > 1
        if has_divergence:
            base += 5 

        if base < 5 and len(req_list) == 1:
            continue

        llm_result = ask_llm_with_context(method, path, req_list)
        
        if not is_idor_candidate(path):
            if "idor" in llm_result.get("tags", []):
                llm_result["tags"].remove("idor")

        if is_auth_endpoint(path):
            llm_result["tags"] = ["auth-flow"]

        if any(r["status"] in (401, 403) for r in req_list):
            llm_result["tags"] = [t for t in llm_result["tags"] if t not in ["auth-bypass"]]

        if not llm_result.get("tags"):
            llm_result["tags"] = ["safe"]

        reason = llm_result.get("reason", "").strip()
        if not reason:
            reason = "rule: no explanation provided"
        if not reason.startswith("llm:") and not reason.startswith("rule:"):
            reason = f"llm: {reason}"
        llm_result["reason"] = reason
        llm_score = llm_result.get("score", 0)
        confidence = llm_result.get("confidence", 0.5)
        final_score = (llm_score * (0.5 + confidence)) + (base * 0.3)

        results.append({
            "score": round(final_score, 2),
            "path": path,
            "method": method,
            "status_variants": sorted(list(status_set)),
            "confidence": confidence,
            "tags": llm_result["tags"],
            "reason": llm_result["reason"]
        })

    return sorted(results, key=lambda x: x["score"], reverse=True)
