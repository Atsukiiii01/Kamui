import argparse
import sys
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from kamui.engine import execute_scan, execute_discovery
from kamui.db import init_db, add_targets, get_pending_targets, mark_completed, reset_db

def load_existing_results(output_path):
    if os.path.exists(output_path):
        with open(output_path, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                pass
    return {"targets": [], "total_hosts_with_open_ports": 0}

def save_results(output_path, data):
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=4)

def main():
    parser = argparse.ArgumentParser(description="Kamui: Industrial Recon Engine with Asynchronous Scaling")
    parser.add_argument("-t", "--target", required=True, help="Target IP or CIDR (e.g., 10.0.0.0/24)")
    parser.add_argument("-p", "--profile", choices=["fast", "full"], default="fast", help="Scan profile")
    parser.add_argument("-o", "--output", default="results.json", help="Output JSON file")
    parser.add_argument("--resume", action="store_true", help="Resume a previously interrupted scan")
    parser.add_argument("-w", "--workers", type=int, default=15, help="Number of concurrent Nmap threads (Default: 15)")
    
    args = parser.parse_args()
    
    print("[*] Initializing Kamui State Manager...")
    
    if not args.resume:
        reset_db()
        init_db()
        print("[*] Initiating Stage 1: Network Discovery...")
        alive_ips = execute_discovery(args.target)
        
        if not alive_ips:
            print("[-] No alive targets discovered. Terminating scan.")
            sys.exit(0)
            
        add_targets(alive_ips)
        print(f"[+] Discovery complete. Isolated {len(alive_ips)} active targets.")
        master_data = {"targets": [], "total_hosts_with_open_ports": 0}
    else:
        init_db()
        print("[*] Resuming previous scan state...")
        master_data = load_existing_results(args.output)
        
    pending_ips = get_pending_targets()
    
    if not pending_ips:
        print("[+] No pending targets found. Scan is already complete.")
        sys.exit(0)
        
    print(f"[*] Commencing Stage 2: Deep Interrogation on {len(pending_ips)} targets.")
    print(f"[*] Scaling out across {args.workers} concurrent workers...")
    print("="*50)
    
    try:
        # Spin up the asynchronous Thread Pool
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            # Submit all pending IPs to the worker pool
            future_to_ip = {executor.submit(execute_scan, ip, args.profile): ip for ip in pending_ips}
            
            # As threads finish, catch them in real-time
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                result = future.result()
                
                # File I/O happens sequentially in the main thread (Thread-Safe)
                if result and result.get("targets"):
                    master_data["targets"].extend(result["targets"])
                    master_data["total_hosts_with_open_ports"] = len(master_data["targets"])
                    
                save_results(args.output, master_data)
                mark_completed(ip)
                print(f"[+] Target {ip} completed. (Vulnerable hosts identified: {master_data['total_hosts_with_open_ports']})")
                
        print("\n" + "="*50)
        print(f"[+] All operations concluded. Final intelligence saved to {args.output}")
        
    except KeyboardInterrupt:
        print("\n[!] Operator aborted the sequence.")
        print(f"[*] Hard-killing asynchronous workers. State has been preserved.")
        # We must use os._exit to immediately kill the hanging daemon threads
        os._exit(130)

if __name__ == "__main__":
    main()