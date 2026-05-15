<div align="center">
  <h1>Kamui </h1>
  <p><b>Asynchronous, State-Aware Reconnaissance Pipeline</b></p>
</div>

---

## Overview

Kamui is a high-speed reconnaissance engine built for Red Team infrastructure. It wraps Nmap's raw scanning capabilities in a fault-tolerant, multithreaded Python architecture. It is designed to execute massive subnet interrogations without losing data to network interruptions, dropped VPNs, or blind sequential bottlenecks.

Instead of dumping raw terminal text, Kamui processes underlying XML outputs into actionable, highly structured JSON data ready for pipeline ingestion.

## Core Architecture

Kamui eliminates the three fundamental flaws of standard port scanning wrappers:

1. **The Timeout Trap (Stage 1 Discovery):** Blindly scanning dead IPs wastes operational time. Kamui initiates a concurrent ICMP/ARP sweep first, isolating only alive targets before deep interrogation begins.
2. **Amnesia (State Management):** Standard scripts lose all data if a scan crashes at 99%. Kamui utilizes a local SQLite database (`kamui_state.db`) to track the exact state of every IP. Passing the `--resume` flag seamlessly bypasses completed targets and resumes exactly where the engine halted.
3. **The Sequential Bottleneck (Concurrency):** Kamui injects an asynchronous `ThreadPoolExecutor` to interrogate multiple targets simultaneously, bypassing single-target limitations while maintaining thread-safe JSON logging.

## Installation & Deployment

Kamui is fully containerized to ensure flawless execution across host operating systems and stripped-down deployment servers.

### Method 1: Docker (Recommended)
Containerization prevents host-OS dependency conflicts and brings a dedicated Nmap environment.

```bash
# Clone the repository
git clone https://github.com/Atsukiiii01/Kamui.git
cd Kamui

# Build the execution engine
docker build -t kamui-engine .
```

### Method 2: Native Host
If running directly on a host, `nmap` must be installed natively, and the script must be run with `root` privileges to allow raw packet crafting during Stage 1 Discovery.

```bash
# Clone and install as a system tool
git clone https://github.com/Atsukiiii01/Kamui.git
cd Kamui
pip install -e .
```

## Operator Usage

### Containerized Execution
*Note: A volume mount (`-v`) is required to extract the `results.json` from the container back to your host machine.*

```bash
# Execute a fast scan with 20 concurrent threads
docker run --rm -v $(pwd):/data kamui-engine -t 192.168.1.0/24 -p fast -o /data/intel.json -w 20
```

### Native Execution

```bash
# Execute a full interrogation pipeline
sudo kamui -t 10.0.0.0/16 -p full -o intel.json -w 15

# Resume an interrupted scan without losing data
sudo kamui -t 10.0.0.0/16 -p full -o intel.json --resume
```

### Command Line Arguments

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target` | Target IP, hostname, or CIDR block (e.g., `10.0.0.0/24`). | **Required** |
| `-p, --profile`| Scanning profile (`fast` for discovery, `full` for deep `-sV -sC`). | `fast` |
| `-o, --output` | Path to save the structured JSON intelligence. | `results.json` |
| `-w, --workers`| Number of concurrent asynchronous worker threads. | `15` |
| `--resume` | Bypasses completed IPs and resumes from the database state. | `False` |

## Output Structure

Kamui aggressively filters out closed/filtered ports. The JSON output strictly contains actionable attack surfaces, extracting the Product, Version, and Extra Info natively.

```json
{
    "targets": [
        {
            "ip": "192.168.1.156",
            "open_ports": [
                {
                    "port": "22",
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "8.9p1 Ubuntu 3ubuntu0.10"
                }
            ]
        }
    ],
    "total_hosts_with_open_ports": 1
}
```

## Disclaimer
Kamui is built strictly for authorized Red Teaming, penetration testing, and academic research. The developer assumes no liability for unauthorized usage.
