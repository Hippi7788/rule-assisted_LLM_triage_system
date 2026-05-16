import json
import sys
from pipeline import process_requests

def load(file):
    with open(file, "r", encoding="utf-8") as f:
        return json.load(f)

def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <burp.json>")
        return

    try:
        data = load(sys.argv[1])
    except Exception as e:
        print(f"[!] Error loading JSON file: {e}")
        return

    print(f"[+] Loaded {len(data)} requests")
    print("[+] Running triage via decoupled architecture...\n")

    results = process_requests(data)

    for r in results[:20]:
        print(f"[{r['score']}] {r['method']} {r['path']}")
        print(f"    signals: {', '.join(r['signals']) if r['signals'] else 'none'}")
        print(f"    confidence: {r['confidence']}\n")

if __name__ == "__main__":
    main()
