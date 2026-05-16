import json
import sys
import os
from pipeline import process_requests

def load(file):
    with open(file, "r", encoding="utf-8") as f:
        return json.load(f)

def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <burp.json>")
        return

    if not os.path.exists("owasp_knowledge.json"):
        print("[!] Warning: owasp_knowledge.json missing! Dynamic scoring will be disabled.")

    try:
        data = load(sys.argv[1])
    except Exception as e:
        print(f"[!] Error loading JSON file: {e}")
        return

    print(f"[+] Loaded {len(data)} requests")
    print("[+] Running triage via data-driven dynamic architecture...\n")

    results = process_requests(data)

    print(f"=== TOP {min(20, len(results))} POTENTIAL ATTACK TARGETS ===\n")

    for r in results[:20]:
        print(f"[{r['score']}] {r['method']} {r['path']}")
        print(f"    signals: {', '.join(r['signals']) if r['signals'] else 'safe'}")
        print(f"    confidence: {r['confidence']}\n")

if __name__ == "__main__":
    main()
