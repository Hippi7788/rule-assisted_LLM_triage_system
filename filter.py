import re
from urllib.parse import urlparse

# 靜態副檔名改用集合（Set）比對速度更快
STATIC_EXT = {".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".map"}

def is_noise(url: str):
    url_low = url.lower()
    parsed = urlparse(url_low)
    path = parsed.path

    # 1. 嚴格檢查副檔名
    if any(path.endswith(ext) for ext in STATIC_EXT):
        return True

    # 2. 只有當噪聲關鍵字出現在路徑的「最後一節（如檔名或目錄名）」才過濾，避免誤殺 /api/static-content
    path_segments = [seg for seg in path.split("/") if seg]
    if path_segments:
        last_segment = path_segments[-1]
        # 常見的靜態資源目錄或檔案關鍵字
        noise_keywords = {"assets", "fonts", "favicon"}
        if last_segment in noise_keywords or any(k in last_segment for k in noise_keywords):
            return True

    return False

def normalize(req):
    url = req.get("url", "/")
    parsed = urlparse(url)
    path = parsed.path

    # 強大的 ID / UUID / 雜湊 正規化，確保去重效果
    path = re.sub(r"/\d+", "/{id}", path)
    path = re.sub(r"/[0-9a-fA-F-]{8,}", "/{uuid}", path)
    path = re.sub(r"/[0-9a-fA-F]{32}", "/{md5_hash}", path) # 新增 MD5 類型的雜湊路徑比對

    # 精準計算參數數量
    param_count = 0
    if parsed.query:
        # 排除空字串與重複 & 的影響
        param_count = len([p for p in parsed.query.split("&") if p])

    return {
        "method": req.get("method", "GET").upper(),
        "path": path,
        "status": int(req.get("status", 0)),
        "length": int(req.get("length", 0)),
        "has_token": bool(req.get("token") or "bearer" in str(req).lower()), # 擴大 Token 的特徵捕捉
        "param_count": param_count
    }

def filter_request(req):
    if is_noise(req.get("url", "")):
        return None
    return normalize(req)
