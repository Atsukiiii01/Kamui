import subprocess
import tempfile
import os
from kamui.parser import parse_nmap_xml
from kamui.parser import parse_nmap_xml, parse_discovery_xml

def execute_scan(target, profile):
    """Executes Nmap silently in the background for threaded concurrency."""
    flags = "-F -T4" if profile == "fast" else "-p- -sV -sC -T4"
    fd, path = tempfile.mkstemp(suffix=".xml")
    os.close(fd)

    try:
        cmd = f"nmap {flags} -oX {path} {target}"
        # We re-enabled capture_output=True to prevent 15 threads from destroying your terminal
        subprocess.run(cmd.split(), capture_output=True, check=True)
        return parse_nmap_xml(path)
    except subprocess.CalledProcessError:
        # If a single thread fails, we don't crash the whole program. We return None.
        return None
    finally:
        if os.path.exists(path):
            os.remove(path)

def execute_discovery(target):
    """Runs a highly concurrent ping sweep to identify alive hosts."""
    fd, path = tempfile.mkstemp(suffix=".xml")
    os.close(fd)

    # Added -v for real-time visibility
    cmd = f"nmap -sn -v -oX {path} {target}"
    
    print(f"[*] Launching Discovery Sweep: {cmd}")
    print("[*] Streaming real-time discovery output below...\n" + "="*50)
    
    try:
        # Removed capture_output=True so Nmap talks to your terminal natively
        subprocess.run(cmd.split(), check=True)
        
        print("="*50 + "\n[*] Discovery execution finished. Parsing alive hosts...")
        alive_ips = parse_discovery_xml(path)
        return alive_ips
        
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Discovery engine failed. Code: {e.returncode}")
    except KeyboardInterrupt:
        print("\n[!] Discovery aborted by operator.")
        raise
    finally:
        if os.path.exists(path):
            os.remove(path)