import requests
import json
import re

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "qwen2.5-coder:1.5b"

def build_context_prompt(method: str, path: str, req_list: list) -> str:
    history_str = ""
    for i, req in enumerate(req_list):
        history_str += f"[{i}] {req['method']} {req['path']} | status={req['status']} | auth={req['has_token']} | params={req['param_count']}\n"

    return f"""You are a Bug Bounty Triage Bot. Analyze the API access history matrix to identify access control risks.

CRITICAL TRIAGE RULES:
1. IDOR SCOPE: Only consider IDOR when there is object-level access (e.g. /user/{{id}}, /file/{{id}}, /order/{{id}}). Do NOT classify authentication endpoints (login, logout, register) as IDOR unless different object resources are accessed across requests.
2. AUTH FLOWS: Authentication endpoints (login, logout, signup, password reset) should be treated as authentication flow analysis only.
3. ADMIN ENDPOINTS: Admin endpoints should be treated as privilege boundary checks, not IDOR candidates unless object-level resources are involved.
4. TEXT OUTPUT: Do not use repeated or templated sentences. Base all reasoning strictly on the provided request history. If evidence is insufficient, explicitly state uncertainty instead of inferring a vulnerability.

🔍 NEW STRICT DIRECTIVES:
- CONFIDENCE: Confidence must reflect evidence strength in the history matrix, not general intuition.
- EVIDENCE ANCHOR: The "reason" MUST reference at least one specific observation index [i] from the history matrix to prove your deduction.
- ALLOWED TAGS: The "tags" array must be selected ONLY from this whitelist: ["idor", "priv-esc", "auth-flow", "auth-bypass", "safe"]. Do not invent other tags.

API Endpoint Context: {method} {path}

Access History Matrix:
{history_str}

Return JSON only:
{{
 "score": <0-100 risk score>,
 "tags": ["idor", "priv-esc", "auth-flow", "auth-bypass", "safe"],
 "confidence": <0.0-1.0 float mapping to empirical matrix evidence>,
 "reason": "<one sentence analysis that MUST contain '[i]' to cite your source evidence>"
}}"""

def clean_json_response(raw_response: str) -> str:
    raw_response = raw_response.strip()
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw_response, re.DOTALL)
    if match:
        return match.group(1)
    return raw_response

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
        "tags": [], 
        "confidence": 0.0, 
        "reason": "invalid_llm_output"
    }

    try:
        r = requests.post(OLLAMA_URL, json=payload, timeout=20)
        r.raise_for_status()
        
        cleaned_json = clean_json_response(r.json().get("response", "{}"))
        res_obj = json.loads(cleaned_json)
        
        if isinstance(res_obj, dict):
            allowed_tags = {"idor", "priv-esc", "auth-flow", "auth-bypass", "safe"}
            if "tags" in res_obj and isinstance(res_obj["tags"], list):
                res_obj["tags"] = [t for t in res_obj["tags"] if t in allowed_tags]
            
            if "confidence" not in res_obj:
                res_obj["confidence"] = 0.5
            return res_obj

        return default_fallback
    except Exception as e:
        default_fallback["reason"] = f"error: {str(e)}"
        return default_fallback
