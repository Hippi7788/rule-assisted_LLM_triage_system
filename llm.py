import requests
import json
import re
import time

OLLAMA_URL = "http://192.168.X.X:11434/api/generate"
MODEL = "qwen2.5-coder:1.5b"

def build_prompt(req_list, method, path):
    history = "\n".join([
        f"[{i}] {r['method']} {r['path']} | status={r['status']} | auth={r['has_token']}"
        for i, r in enumerate(req_list)
    ])

    return f"""[Run ID: {int(time.time())}]
You are a security matrix analyzer. Your ONLY job is to extract attack signals from the history.

ALLOWED SIGNALS:
- idor_sig: Multiple requests accessing object-level ID/UUID resource paths.
- auth_flip: Mix of true and false auth status within this group.
- priv_anomaly: Unauthenticated status returned normal 200 or restricted data.
- safe: No access control anomalies or parameter variances present.

Endpoint Context: {method} {path}
Observations: {len(req_list)}

History Matrix:
{history}

Strictly return JSON in this exact format, with no conversation or other fields.
Example Output:
{{
  "signals": ["idor_sig"],
  "confidence": 0.90
}}
"""

def clean_json_response(raw_response: str) -> str:
    raw_response = raw_response.strip()
    start_idx = raw_response.find("{")
    end_idx = raw_response.rfind("}")
    if start_idx == -1 or end_idx == -1: return "{}"
    return raw_response[start_idx:end_idx+1]

def ask_llm(req_list, method, path):
    dynamic_temp = 0.0 + (int(time.time() * 1000) % 10) * 0.001 

    payload = {
        "model": MODEL,
        "prompt": build_prompt(req_list, method, path),
        "stream": False,
        "format": "json",
        "options": {
            "temperature": dynamic_temp,
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
        extracted_signals = []

        if "signals" in data and isinstance(data["signals"], list):
            extracted_signals = data["signals"]
            
        elif "events" in data and isinstance(data["events"], list):
            for ev in data["events"]:
                if isinstance(ev, dict) and "signal" in ev:
                    extracted_signals.append(ev["signal"])
                    
        signals = [s for s in extracted_signals if s in allowed_signals]
        confidence = float(data.get("confidence", 0.85 if len(signals) > 0 and "safe" not in signals else 0.5))

        return {
            "signals": signals if signals else ["safe"],
            "confidence": min(1.0, max(0.0, confidence))
        }
    except:
        return {"signals": ["safe"], "confidence": 0.0}
