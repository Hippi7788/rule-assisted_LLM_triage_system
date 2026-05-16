import re
from urllib.parse import urlparse

STATIC_EXT = {".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".map"}

def is_noise(url: str) -> bool:
    if not url:
        return True
    url_low = url.lower()
    parsed = urlparse(url_low)
    path = parsed.path

    if any(path.endswith(ext) for ext in STATIC_EXT):
        return True

    path_segments = [seg for seg in path.split("/") if seg]
    if path_segments:
        last_segment = path_segments[-1]
        noise_keywords = {"assets", "fonts", "favicon"}
        if last_segment in noise_keywords or any(k in last_segment for k in noise_keywords):
            return True
    return False

def check_auth_present(req: dict) -> bool:
    if req.get("token"):
        return True
        
    headers = req.get("headers", "")

    if isinstance(headers, list):
        headers = " ".join(map(str, headers))
    elif isinstance(headers, dict):
        headers = str(headers)
        
    headers_low = headers.lower()
    auth_signals = ["authorization", "bearer", "cookie", "xsrf-token", "x-api-key"]
    return any(sig in headers_low for sig in auth_signals)

def normalize(req: dict) -> dict:
    url = req.get("url", "/")
    parsed = urlparse(url)
    path = parsed.path if parsed.path else "/"

    uuid_pattern = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    path = re.sub(f"/{uuid_pattern}", "/{uuid}", path)
    path = re.sub(r"/[0-9a-fA-F]{32}", "/{hash}", path)
    path = re.sub(r"/\d+", "/{id}", path)

    param_count = 0
    if parsed.query:
        param_count = len([p for p in parsed.query.split("&") if p])

    return {
        "method": str(req.get("method", "GET")).upper(),
        "path": path,
        "status": int(req.get("status", 0)),
        "length": int(req.get("length", 0)),
        "has_token": check_auth_present(req),
        "param_count": param_count
    }

def filter_request(req: dict):
    if is_noise(req.get("url", "")):
        return None
    return normalize(req)
