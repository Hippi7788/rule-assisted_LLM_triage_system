import json
import sys
from pipeline import process_requests

def load(file):
    with open(file, "r", encoding="utf-8") as f:
        return json.load(f)

def main():
    if len(sys.argv) < 2:
        print("[!] Usage: python main.py <burp_output.json>")
        return

    try:
        data = load(sys.argv[1])
        if not isinstance(data, list):
            print("[!] Error: JSON file must contain a list of requests.")
            return
    except Exception as e:
        print(f"[!] Error loading JSON file: {e}")
        return

    print(f"[+] Loaded {len(data)} total requests raw data.")
    print("[+] Processing and analyzing via AI pipeline (this may take a while)...")

    results = process_requests(data)

    print(f"\n=== TOP {min(20, len(results))} POTENTIAL VULNERABILITY TARGETS ===\n")

    for r in results[:20]:
        print(f"[{r['score']}] {r['method']} {r['path']}")
        print(f"    Tags  : {', '.join(r['tags']) if r['tags'] else 'None'}")
        print(f"    Reason: {r['reason']}\n")

if __name__ == "__main__":
    main()
