import requests
import json
import re
import time

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "qwen2.5-coder:1.5b"

def build_context_prompt(method: str, path: str, req_list: list) -> str:
    history_str = ""
    for i, req in enumerate(req_list):
        history_str += f"[{i}] {req['method']} {req['path']} | status={req['status']} | auth={req['has_token']} | params={req['param_count']}\n"

    return f"""[Run ID: {int(time.time())}]
You are a Bug Bounty Triage Bot. Analyze the API access history matrix to identify access control risks.

CRITICAL TRIAGE RULES:
1. IDOR SCOPE: Only consider IDOR when there is object-level access (e.g. /user/{{id}}, /file/{{id}}, /order/{{id}}). Do NOT classify authentication endpoints (login, logout, register) as IDOR unless different object resources are accessed across requests.
2. AUTH FLOWS: Authentication endpoints (login, logout, signup, password reset) should be treated as authentication flow analysis only.
3. ADMIN ENDPOINTS: Admin endpoints should be treated as privilege boundary checks, not IDOR candidates unless object-level resources are involved.
4. TEXT OUTPUT: Do not use repeated or templated sentences. Base all reasoning strictly on the provided request history. If evidence is insufficient, explicitly state uncertainty instead of inferring a vulnerability.

SECURITY CORE DIRECTIVES (IMPORTANT RULES):
- 403 / 401 is NOT a vulnerability by itself. Authentication failure is NORMAL behavior.
- Only flag vulnerability when unauthorized access returns 200 or data leakage occurs.
- CONFIDENCE: Confidence must reflect evidence strength in the history matrix, not general intuition.
- EVIDENCE ANCHOR: The "reason" MUST reference at least one specific observation index like '[i]' from the history matrix to prove your deduction.

TAGS PRIORITY (MUST SELECT ONLY FROM THIS LIST):
- auth-flow (always first if login/logout/signup)
- idor (ONLY object access like /user/{{id}})
- auth-bypass (ONLY when 200 without auth expected)
- safe (default, must dominate)

API Endpoint Context: {method} {path}
Number of observations in this endpoint group: {len(req_list)}

Access History Matrix:
{history_str}

Return JSON only:
{{
 "score": <0-100 risk score>,
 "tags": ["safe"],
 "confidence": <0.0-1.0 float>,
 "reason": "<one sentence citing exact '[i]' evidence>"
}}"""

def clean_json_response(raw_response: str) -> str:
    raw_response = raw_response.strip()
    start = raw_response.find("{")
    end = raw_response.rfind("}")

    if start == -1 or end == -1:
        return "{}"

    return raw_response[start:end+1]

def ask_llm_with_context(method: str, path: str, req_list: list) -> dict:
    payload = {
        "model": MODEL,
        "prompt": build_context_prompt(method, path, req_list),
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.0,
            "top_p": 0.1,
            "num_ctx": 512,
            "num_predict": 128 
        }
    }

    default_fallback = {
        "score": 0,
        "tags": ["safe"],
        "confidence": 0.0,
        "reason": "rule: fallback"
    }

    try:
        r = requests.post(OLLAMA_URL, json=payload, timeout=20)
        r.raise_for_status()
        
        cleaned_json = clean_json_response(r.json().get("response", "{}"))
        
        try:
            res_obj = json.loads(cleaned_json)
        except json.JSONDecodeError:
            fb = default_fallback.copy()
            fb["reason"] = "rule: fallback (json_parse_failed)"
            return fb
        
        if isinstance(res_obj, dict):
            allowed_tags = {"idor", "priv-esc", "auth-flow", "auth-bypass", "safe"}
            if "tags" in res_obj and isinstance(res_obj["tags"], list):
                res_obj["tags"] = [t for t in res_obj["tags"] if t in allowed_tags]
            
            if "confidence" not in res_obj:
                res_obj["confidence"] = 0.5
            return res_obj

    except Exception as e:
        fb = default_fallback.copy()
        fb["reason"] = f"rule: fallback (api_error: {str(e)})"
        return fb
        
    return default_fallback
