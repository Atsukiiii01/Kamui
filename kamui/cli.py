import argparse
import sys
import json
from kamui.engine import execute_scan

def main():
    parser = argparse.ArgumentParser(description="Kamui: Industrial Recon Engine")
    parser.add_argument("-t", "--target", required=True, help="Target IP or CIDR")
    parser.add_argument("-p", "--profile", choices=["fast", "full"], default="fast")
    parser.add_argument("-o", "--output", default="results.json", help="Output file")
    
    args = parser.parse_args()
    
    print(f"[*] Kamui Engine Active. Scanning: {args.target}")
    try:
        data = execute_scan(args.target, args.profile)
        with open(args.output, "w") as f:
            json.dump(data, f, indent=4)
        print(f"[+] Intelligence saved to {args.output}")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()