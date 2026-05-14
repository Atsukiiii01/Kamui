import argparse
import sys
import json
import os
from kamui.engine import execute_scan
from kamui.utils import parse_targets
from kamui.db import init_db, add_targets, get_pending_targets, mark_completed, reset_db

def load_existing_results(output_path):
    """Loads existing JSON data to merge with new results during a resumed scan."""
    if os.path.exists(output_path):
        with open(output_path, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {"targets": [], "total_hosts_with_open_ports": 0}
    return {"targets": [], "total_hosts_with_open_ports": 0}

def save_results(output_path, data):
    """Writes the JSON to disk safely."""
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=4)

def main():
    parser = argparse.ArgumentParser(description="Kamui: Industrial Recon Engine with State Persistence")
    parser.add_argument("-t", "--target", required=True, help="Target IP or CIDR (e.g., 10.0.0.0/24)")
    parser.add_argument("-p", "--profile", choices=["fast", "full"], default="fast", help="Scan profile")
    parser.add_argument("-o", "--output", default="results.json", help="Output JSON file")
    parser.add_argument("--resume", action="store_true", help="Resume a previously interrupted scan")
    
    args = parser.parse_args()
    
    print("[*] Initializing Kamui State Manager...")
    
    if not args.resume:
        # Fresh scan: Wipe old memory, parse the CIDR, insert to DB
        reset_db()
        init_db()
        ips = parse_targets(args.target)
        add_targets(ips)
        print(f"[*] New scan initialized. Loaded {len(ips)} targets into the database.")
        master_data = {"targets": [], "total_hosts_with_open_ports": 0}
    else:
        # Resume scan: Keep DB intact, load previous JSON to append to it
        init_db()
        print("[*] Resuming previous scan state...")
        master_data = load_existing_results(args.output)
        
    pending_ips = get_pending_targets()
    
    if not pending_ips:
        print("[+] No pending targets found. Scan is already complete.")
        sys.exit(0)
        
    print(f"[*] Targets remaining: {len(pending_ips)}")
    print("="*50)
    
    try:
        for ip in pending_ips:
            print(f"\n[*] Launching engine against: {ip}")
            
            # 1. Execute engine against a single IP
            result = execute_scan(ip, args.profile)
            
            # 2. Merge data if open ports were found
            if result and result.get("targets"):
                master_data["targets"].extend(result["targets"])
                master_data["total_hosts_with_open_ports"] = len(master_data["targets"])
                
            # 3. Save incremental progress to disk immediately
            save_results(args.output, master_data)
            
            # 4. Mark as completed in the database
            mark_completed(ip)
            print(f"[+] Target {ip} completed and state saved.")
            
        print("\n" + "="*50)
        print(f"[+] All targets completed. Final intelligence saved to {args.output}")
        
    except KeyboardInterrupt:
        print("\n[!] Operator aborted the sequence. State has been preserved.")
        print(f"[*] To resume, run the exact same command but add the --resume flag.")
        sys.exit(130)
    except Exception as e:
        print(f"\n[-] Fatal structural failure: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()