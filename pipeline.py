from filter import filter_request
from llm import ask_llm

def heuristic_score(req):
    """
    啟發式評分：僅作為先驗修正值（Prior Bias）
    最高理論分數約為 36 分，乘以 0.3 後最大修正幅度約 +10 分
    """
    score = 0
    path = req["path"].lower()

    # 1. 核心認證信號
    if req["has_token"]:
        score += 8

    # 2. 結構信號（Api 弱加分）
    if "/api" in path:
        score += 6

    # 3. 敏感區域弱權重
    if any(x in path for x in ["/admin", "/user", "/account", "/setting", "/config"]):
        score += 8

    # 4. 狀態碼觀察信號（Bug Bounty 中 403/401 往往比單純的 500 更有權限繞過價值）
    if req["status"] == 403:
        score += 8
    elif req["status"] == 401:
        score += 6
    elif req["status"] == 500:
        score += 8

    # 5. 參數密集度
    if req["param_count"] > 3:
        score += 4

    return score

def process_requests(requests_data):
    results = []
    seen_endpoints = set() # 用於去重的集合

    for req in requests_data:
        cleaned = filter_request(req)
        if not cleaned:
            continue

        # 【問題 4 修正】去重粒度放寬：納入 status，避免誤殺不同響應狀態的高價值 API
        fingerprint = f"{cleaned['method']}:{cleaned['path']}:{cleaned['status']}"
        if fingerprint in seen_endpoints:
            continue
        
        # 計算基礎修正分
        base = heuristic_score(cleaned)

        # 這裡可以保留低於特定修正分就跳過的邏輯，或者如果想全送 LLM 評估，可將門檻設低
        if base < 5: 
            continue

        # 標記已處理過此狀態的端點
        seen_endpoints.add(fingerprint)

        # 呼叫 LLM 進行主體評估
        llm_result = ask_llm(cleaned)
        llm_score = llm_result.get("score", 0)

        # 【問題 2 修正】LLM 分數為主體，Heuristic 分數為修正值
        final_score = llm_score + (base * 0.3)

        results.append({
            "score": round(final_score, 2), # 四捨五入保持輸出美觀
            "path": cleaned["path"],
            "method": cleaned["method"],
            "status": cleaned["status"],
            "tags": llm_result.get("tags", []),
            "reason": llm_result.get("reason", "")
        })

    # 依最終權重分數由高到低排序
    return sorted(results, key=lambda x: x["score"], reverse=True)
