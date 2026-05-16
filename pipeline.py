from filter import filter_request
from llm import ask_llm_with_context
from collections import defaultdict

def heuristic_score(req: dict) -> int:
    """啟發式評分：作為先驗知識修正值（Base Priority）"""
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

        if base < 5 and len(req_list) == 1:
            continue

        llm_result = ask_llm_with_context(method, path, req_list)
        
        llm_score = llm_result.get("score", 0)
        confidence = llm_result.get("confidence", 0.5)
        final_score = llm_score + (confidence * 10) + (base * 0.3)

        results.append({
            "score": round(final_score, 2),
            "path": path,
            "method": method,
            "status_variants": [r['status'] for r in req_list],
            "confidence": confidence,
            "tags": llm_result.get("tags", []),
            "reason": llm_result.get("reason", "")
        })

    # 依最終總分由高到低排序
    return sorted(results, key=lambda x: x["score"], reverse=True)
