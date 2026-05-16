import requests
import json
import re

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "qwen2.5-coder:1.5b"

def build_prompt(req_list, method, path):
    history = "\n".join([
        f"[{i}] {r['method']} {r['path']} | status={r['status']} | auth={r['has_token']}"
        for i, r in enumerate(req_list)
    ])

    return f"""You are a security signal extractor for an endpoint group. Do NOT decide vulnerabilities. ONLY extract observable signals from the history matrix.

Return JSON ONLY:
{{
  "signals": ["idor_signal", "auth_anomaly", "status_inconsistency", "safe"],
  "confidence": 0.0
}}

Endpoint Context: {method} {path}
Number of Observations: {len(req_list)}

History Matrix:
{history}
"""

def clean_json_response(raw_response: str) -> str:
    """物理大括號切片法：防止 Qwen 夾帶 Markdown 標籤導致 json.loads 崩潰"""
    raw_response = raw_response.strip()
    start = raw_response.find("{")
    end = raw_response.rfind("}")
    if start == -1 or end == -1:
        return "{}"
    return raw_response[start:end+1]

def ask_llm(req_list, method, path):
    payload = {
        "model": MODEL,
        "prompt": build_prompt(req_list, method, path),
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.0,
            "num_ctx": 512,
            "num_predict": 80
        }
    }

    try:
        r = requests.post(OLLAMA_URL, json=payload, timeout=20)
        r.raise_for_status()
        cleaned_json = clean_json_response(r.json().get("response", "{}"))
        data = json.loads(cleaned_json)
        allowed_signals = {"idor_signal", "auth_anomaly", "status_inconsistency", "safe"}
        raw_signals = data.get("signals", [])
        signals = [s for s in raw_signals if s in allowed_signals] if isinstance(raw_signals, list) else []

        return {
            "signals": signals if signals else ["safe"],
            "confidence": min(1.0, max(0.0, float(data.get("confidence", 0.5))))
        }
    except:
        return {
            "signals": ["safe"],
            "confidence": 0.0
        }
