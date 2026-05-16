import requests
import json
import re

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.1"

def build_prompt(req: dict) -> str:
    return f"""Bug bounty triage. Score request risk (0-100).

Focus Areas:
- Auth Bypass / IDOR (e.g., state changes, user privacy paths)
- Sensitive Endpoints (e.g., internal APIs, admin/debug functions)
- Abnormal Responses (e.g., unexpected 500/403/401 status)

Scoring Guide:
- 80-100: Critical/High Risk (Data destruction, state-changing admin actions, clear IDOR indicators)
- 40-79: Medium Risk (Standard authenticated APIs with parameters, potential info leak paths)
- 0-39: Low Risk (Public assets, landing pages, static informational queries)

REQUEST INFO:
Method: {req["method"]}
Path: {req["path"]}
Status: {req["status"]}
Auth_Token_Present: {req["has_token"]}
Params_Count: {req["param_count"]}

Return strictly a single JSON object. No conversation, no markdown wrapper.
Format:
{{
 "score": <0-100 integer>,
 "tags": [<string tokens>],
 "reason": "<one sentence explanation>"
}}
"""

def clean_json_response(raw_response: str) -> str:
    raw_response = raw_response.strip()
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw_response, re.DOTALL)
    if match:
        return match.group(1)
    return raw_response

def ask_llm(req: dict) -> dict:
    payload = {
        "model": MODEL,
        "prompt": build_prompt(req),
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.1,
            "top_p": 0.7,
            "num_ctx": 512
        }
    }

    default_fallback = {"score": 0, "tags": [], "reason": "parse_failed"}

    try:
        r = requests.post(OLLAMA_URL, json=payload, timeout=30)
        r.raise_for_status()
        data = r.json()
        
        cleaned_json = clean_json_response(data.get("response", "{}"))
        res_obj = json.loads(cleaned_json)
        
        if isinstance(res_obj, dict):
            return res_obj
        return default_fallback
        
    except Exception as e:
        default_fallback["reason"] = f"error: {str(e)}"
        return default_fallback
