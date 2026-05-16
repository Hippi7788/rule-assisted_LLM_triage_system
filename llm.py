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

HINT ONLY:
Possible IDOR patterns:
- auth mismatch across requests
- inconsistent access control

API Endpoint Context: {method} {path}

Access History Matrix:
{history_str}

Return JSON only:
{{
 "score": <0-100 risk score>,
 "tags": [<relevant security labels>],
 "confidence": <0.0-1.0 float estimating your deduction accuracy>,
 "reason": "<one sentence analysis based on history>"
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
            if "confidence" not in res_obj:
                res_obj["confidence"] = 0.5
            return res_obj

        return default_fallback
    except Exception as e:
        default_fallback["reason"] = f"error: {str(e)}"
        return default_fallback
