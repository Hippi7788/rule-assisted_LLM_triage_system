import requests
import json
import re
import time

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "qwen2.5-coder:1.5b"

def build_prompt(req_list, method, path):
    history = "\n".join([
        f"[{i}] {r['method']} {r['path']} | status={r['status']} | auth={r['has_token']}"
        for i, r in enumerate(req_list)
    ])
    
    return f"""[Run ID: {int(time.time())}]
You are a security history analyzer. Extract observed event patterns from the history matrix.

ALLOWED SIGNALS (SELECT ONLY FROM THIS LIST):
- idor_sig: Observed multiple requests accessing object-level ID/UUID resource paths.
- auth_flip: Observed explicit mix of true and false auth status within this group.
- priv_anomaly: Unauthenticated or low-privilege status returned normal 200 or restricted data.
- safe: Default signal if no access control anomalies or parameter variances are present.

Return JSON ONLY:
{{
  "signals": ["safe"],
  "confidence": 0.0
}}

Endpoint: {method} {path}
Observations Count: {len(req_list)}

History Matrix:
{history}
"""

def clean_json_response(raw_response: str) -> str:
    raw_response = raw_response.strip()
    start_idx = raw_response.find("{")
    end_idx = raw_response.rfind("}")
    if start_idx == -1 or end_idx == -1: return "{}"
    return raw_response[start_idx:end_idx+1]

def ask_llm(req_list, method, path):
    payload = {
        "model": MODEL,
        "prompt": build_prompt(req_list, method, path),
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.0,
            "num_ctx": 512,
            "num_predict": 60
        }
    }

    try:
        r = requests.post(OLLAMA_URL, json=payload, timeout=20)
        r.raise_for_status()
        
        cleaned_json = clean_json_response(r.json().get("response", "{}"))
        data = json.loads(cleaned_json)
        allowed_signals = {"idor_sig", "auth_flip", "priv_anomaly", "safe"}
        raw_signals = data.get("signals", [])
        signals = [s for s in raw_signals if s in allowed_signals] if isinstance(raw_signals, list) else []

        return {
            "signals": signals if signals else ["safe"],
            "confidence": min(1.0, max(0.0, float(data.get("confidence", 0.5))))
        }
    except:
        return {"signals": ["safe"], "confidence": 0.0}
