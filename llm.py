import requests
import json
import re

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.1"

def build_prompt(req):
    # 【問題 3 修正】結構化 Focus，並為 0-100 分數提供 Anchor 錨定基準，防止 Llama 隨機亂打分
    return f"""Bug bounty triage. Score request risk (0-100).

Focus Areas:
- Auth Bypass / IDOR (e.g., /user/ settings, state changes)
- Sensitive Endpoints (e.g., /admin, /internal, private APIs)
- Abnormal Responses (e.g., 500 errors, unexpected 403/401)

Scoring Guide:
- 80-100: Critical/High Risk (State-changing admin actions, explicit IDOR targets, 500 on auth endpoints)
- 40-79: Medium Risk (Standard APIs with params, sensitive data paths with auth required)
- 0-39: Low Risk (Public endpoints, static-like queries, standard low-value paths)

REQUEST:
Method: {req["method"]}
Path: {req["path"]}
Status: {req["status"]}
Auth_Present: {req["has_token"]}
Params_Count: {req["param_count"]}

Return JSON only:
{{
 "score": <0-100 integer>,
 "tags": [<relevant safety tokens like "idor", "priv-esc", "sqli", "info-leak">],
 "reason": "<one sentence concise justification>"
}}
"""

def clean_json_response(raw_response):
    raw_response = raw_response.strip()
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw_response, re.DOTALL)
    if match:
        return match.group(1)
    return raw_response

def ask_llm(req):
    payload = {
        "model": MODEL,
        "prompt": build_prompt(req),
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.1, # 保持低隨機性
            "top_p": 0.7,
            "num_ctx": 512
        }
    }

    try:
        r = requests.post(OLLAMA_URL, json=payload, timeout=30)
        r.raise_for_status()
        data = r.json()
        
        cleaned_json = clean_json_response(data.get("response", "{}"))
        return json.loads(cleaned_json)
    except Exception as e:
        return {
            "score": 0,
            "tags": [],
            "reason": f"parse_failed: {str(e)}"
        }
