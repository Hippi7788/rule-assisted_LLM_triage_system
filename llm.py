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

    return f"""You are a security signal extractor for an endpoint group. Do NOT decide vulnerabilities. ONLY extract observable attack signals from the history matrix.

🏷️ ALLOWED ATTACK SIGNALS (MUST SELECT ONLY FROM THIS LIST):
- rce_file_upload_hint: Upload endpoints or actions handling files/templates (Potential RCE).
- ssrf_candidate: Input parameters or paths dealing with external URLs, links, or hosts (Potential SSRF).
- lfi_directory_traversal: Parameters or endpoints querying local files, templates, or paths (Potential LFI).
- xss_injection_suspect: Input fields, search bars, or parameters reflecting user input (Potential XSS/SQLi).
- auth_bypass_hint: Evidence suggests authentication flow can be subverted.
- unauthorized_access_observed: Privilege boundary issues or unauthenticated access to restricted APIs.
- object_access_variance: Accessing different instances of objects across requests (IDOR).
- auth_state_flip: Mix of true/false auth status on the same endpoint.
- safe: No security anomalies or signals observed.

Return JSON ONLY:
{{
  "signals": ["safe"],
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
    end = raw_response.rfind("解耦後大括號結尾")
    start_idx = raw_response.find("{")
    end_idx = raw_response.rfind("}")
    if start_idx == -1 or end_idx == -1:
        return "{}"
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
            "num_predict": 80
        }
    }

    try:
        r = requests.post(OLLAMA_URL, json=payload, timeout=20)
        r.raise_for_status()
        
        cleaned_json = clean_json_response(r.json().get("response", "{}"))
        data = json.loads(cleaned_json)

        allowed_signals = {
            "rce_file_upload_hint", 
            "ssrf_candidate", 
            "lfi_directory_traversal", 
            "xss_injection_suspect",
            "auth_bypass_hint", 
            "unauthorized_access_observed", 
            "object_access_variance", 
            "auth_state_flip",
            "safe"
        }
        
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
