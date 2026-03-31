import asyncio
import logging
import sys
from kamui_bridge import AsyncKamuiBridge
from kamui_intel import run_pipeline

# Force logging to print to the terminal so you can watch the engine work
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

async def main():
    print("[*] Initializing Kamui Async Bridge...")
    
    # Initialize the bridge
    bridge = AsyncKamuiBridge(
        pipeline_func=run_pipeline,
        api_key="", 
        min_score=7.0,
        output_dir="kamui_output"
    )

    # Define a safe test target (scanme.nmap.org is explicitly legal to scan)
    target = "scanme.nmap.org"
    cmd = ["nmap", "-sS", "-sV", "-T4", target]

    print(f"[*] Dispatching Command: {' '.join(cmd)}")

    # We use an asyncio.Event to keep the main thread alive until the callback fires
    scan_finished = asyncio.Event()

    def on_output(msg):
        print(f"  [NMAP] {msg}")

    def on_complete(results):
        print("\n[+] PIPELINE COMPLETE. Intelligence Data:")
        # Print a quick summary of the JSON data
        for ip, host_data in results.items():
            print(f"    Target: {ip}")
            for port, port_data in host_data["ports"].items():
                cve_count = len(port_data['cves'])
                print(f"    -> Port {port} ({port_data['cpe']}): {cve_count} High/Critical CVEs found.")
        scan_finished.set()

    def on_error(err):
        print(f"\n[!] PIPELINE FAILED: {err}")
        scan_finished.set()

    # Trigger the scan
    bridge.run_scan(
        cmd_list=cmd,
        output_cb=on_output,
        complete_cb=on_complete,
        error_cb=on_error
    )

    # Wait for the callbacks to signal completion
    await scan_finished.wait()
    
    # Graceful shutdown
    await bridge.shutdown()

if __name__ == "__main__":
    # Windows requires this specific event loop policy for async subprocesses
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    asyncio.run(main())