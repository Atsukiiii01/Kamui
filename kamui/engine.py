import subprocess
import tempfile
import os
from kamui.parser import parse_nmap_xml

def execute_scan(target, profile):
    # Base flags
    flags = "-F -T4" if profile == "fast" else "-p- -sV -sC -T4"
    
    # Force verbosity so the operator sees real-time progress
    flags += " -v"
    
    fd, path = tempfile.mkstemp(suffix=".xml")
    os.close(fd)

    print(f"[*] Engine Command: nmap {flags} {target}")
    print("[*] Streaming real-time engine output below...\n" + "="*50)

    try:
        cmd = f"nmap {flags} -oX {path} {target}"
        # Removed 'capture_output=True'. 
        # This allows Nmap to talk directly to your terminal screen natively.
        subprocess.run(cmd.split(), check=True)
        
        print("="*50 + "\n[*] Engine execution finished. Extracting structural intelligence...")
        return parse_nmap_xml(path)
        
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Engine failure or manual abort. Code: {e.returncode}")
    except KeyboardInterrupt:
        print("\n[!] Scan aborted by operator.")
        raise
    finally:
        if os.path.exists(path):
            os.remove(path)