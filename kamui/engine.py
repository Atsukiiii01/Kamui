import subprocess
import tempfile
import os
from kamui.parser import parse_nmap_xml

def execute_scan(target, profile):
    flags = "-F -T4" if profile == "fast" else "-p- -sV -sC -T4"
    fd, path = tempfile.mkstemp(suffix=".xml")
    os.close(fd)

    try:
        # Running Nmap headlessly with XML output
        cmd = f"nmap {flags} -oX {path} {target}"
        subprocess.run(cmd.split(), capture_output=True, check=True)
        return parse_nmap_xml(path)
    finally:
        if os.path.exists(path):
            os.remove(path)