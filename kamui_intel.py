"""
kamui_intel_v6.py
=================
The terminal architecture for the Kamui Intelligence Pipeline.
Implements Producer/Consumer workers, Priority Queues, Circuit Breakers,
Persistent WAL SQLite caching, and Incremental JSONL streaming.
"""

import asyncio
import aiohttp
import aiosqlite
import xml.etree.ElementTree as ET
import logging
import re
import json
import time
from pathlib import Path
from typing import Any, Callable, Optional, Dict, List, Tuple
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Configuration & Constants
# ---------------------------------------------------------------------------
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_EXPIRY_SEC = 7 * 24 * 60 * 60
WORKER_POOL_SIZE = 50
CIRCUIT_BREAKER_THRESHOLD = 5
CIRCUIT_BREAKER_RECOVERY_SEC = 60
API_TIMEOUT_SEC = 15

# Ports prioritized in the queue (e.g., common web/admin interfaces)
CRITICAL_PORTS = {22, 80, 443, 445, 3389, 8080, 8443}

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("kamui.intel.v6")

_PRODUCT_MAP = {
    re.compile(r'\bapache httpd\b'): ("apache", "http_server"),
    re.compile(r'\bapache\b'): ("apache", "http_server"),
    re.compile(r'\bopenssh\b'): ("openbsd", "openssh"),
    re.compile(r'\bnginx\b'): ("nginx", "nginx"),
    re.compile(r'\biis\b'): ("microsoft", "iis"),
    re.compile(r'\bmicrosoft-iis\b'): ("microsoft", "iis"),
    re.compile(r'\bmysql\b'): ("oracle", "mysql"),
    re.compile(r'\bproftpd\b'): ("proftpd", "proftpd"),
    re.compile(r'\bvsftpd\b'): ("vsftpd", "vsftpd"),
}

# ---------------------------------------------------------------------------
# Core Infrastructure
# ---------------------------------------------------------------------------
class CircuitBreaker:
    def __init__(self):
        self.failures = 0
        self.tripped_until = 0.0

    def record_failure(self):
        self.failures += 1
        if self.failures >= CIRCUIT_BREAKER_THRESHOLD:
            log.critical("CIRCUIT BREAKER TRIPPED. Halting API traffic.")
            self.tripped_until = time.time() + CIRCUIT_BREAKER_RECOVERY_SEC

    def record_success(self):
        self.failures = 0

    @property
    def is_tripped(self) -> bool:
        return time.time() < self.tripped_until

    async def wait_if_tripped(self):
        while self.is_tripped:
            await asyncio.sleep(1)


class PersistentCacheDB:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db: Optional[aiosqlite.Connection] = None

    async def connect(self):
        self.db = await aiosqlite.connect(self.db_path)
        await self.db.execute("PRAGMA journal_mode=WAL;")
        await self.db.execute("PRAGMA synchronous=NORMAL;")
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS cve_cache (
                cpe TEXT PRIMARY KEY, data TEXT, timestamp REAL
            )
        """)
        await self.db.commit()

    async def close(self):
        if self.db:
            await self.db.close()

    async def get(self, cpe: str) -> Optional[list]:
        async with self.db.execute("SELECT data, timestamp FROM cve_cache WHERE cpe = ?", (cpe,)) as cursor:
            row = await cursor.fetchone()
            if row and (time.time() - row[1] < CACHE_EXPIRY_SEC):
                try:
                    return json.loads(row[0])
                except json.JSONDecodeError:
                    await self.db.execute("DELETE FROM cve_cache WHERE cpe = ?", (cpe,))
                    await self.db.commit()
        return None

    async def set(self, cpe: str, data: list):
        await self.db.execute("INSERT OR REPLACE INTO cve_cache VALUES (?, ?, ?)", 
                              (cpe, json.dumps(data), time.time()))
        await self.db.commit()


class SharedNVDClient:
    def __init__(self, api_key: Optional[str], cache: PersistentCacheDB):
        self.api_key = api_key
        self.cache = cache
        self.breaker = CircuitBreaker()

    async def fetch_cves(self, session: aiohttp.ClientSession, cpe: str) -> list:
        if not cpe or "unknown" in cpe: return []
        
        cached = await self.cache.get(cpe)
        if cached is not None: return cached

        await self.breaker.wait_if_tripped()

        headers = {"Accept-Encoding": "gzip, deflate", "User-Agent": "Kamui-Intel-Engine/6.0"}
        if self.api_key: headers["apiKey"] = self.api_key
        params = {"cpeName": cpe}

        try:
            async with session.get(NVD_API_URL, params=params, headers=headers, 
                                   timeout=aiohttp.ClientTimeout(total=API_TIMEOUT_SEC)) as resp:
                if resp.status == 200:
                    try:
                        raw = await resp.json()
                        vulns = raw.get("vulnerabilities", [])
                        await self.cache.set(cpe, vulns)
                        self.breaker.record_success()
                        return vulns
                    except json.JSONDecodeError:
                        self.breaker.record_failure()
                elif resp.status in (429, 503):
                    self.breaker.record_failure()
                elif resp.status == 404:
                    await self.cache.set(cpe, [])
                    return []
                else:
                    self.breaker.record_failure()
        except (asyncio.TimeoutError, aiohttp.ClientError):
            self.breaker.record_failure()
            
        return []

# ---------------------------------------------------------------------------
# Data Processing & Parsing
# ---------------------------------------------------------------------------
@dataclass(order=True)
class TaskItem:
    priority: int
    timestamp: float
    ip: str = field(compare=False)
    port_id: int = field(compare=False)
    protocol: str = field(compare=False)
    cpe: str = field(compare=False)
    service_info: dict = field(compare=False)

def stream_nmap_xml(xml_path: str):
    """Yields parsed port data incrementally to feed the Producer."""
    current_ip = None
    try:
        context = ET.iterparse(xml_path, events=("start", "end"))
        for event, elem in context:
            if event == "start" and elem.tag == "host":
                current_ip = ""
            elif event == "end" and elem.tag == "address":
                if elem.get("addrtype") in ("ipv4", "ipv6"):
                    current_ip = elem.get("addr", "")
            elif event == "end" and elem.tag == "port":
                state_elem = elem.find("state")
                if current_ip and state_elem is not None and state_elem.get("state") == "open":
                    svc_elem = elem.find("service")
                    svc = svc_elem.get("name", "") if svc_elem is not None else ""
                    prod = svc_elem.get("product", "") if svc_elem is not None else ""
                    ver = svc_elem.get("version", "") if svc_elem is not None else ""
                    
                    # Normalize CPE
                    banner = (prod or svc).strip().lower()
                    vendor, prod_name = "unknown", banner.replace(" ", "_")
                    for regex, (m_vendor, m_prod) in _PRODUCT_MAP.items():
                        if regex.search(banner):
                            vendor, prod_name = m_vendor, m_prod
                            break
                    cpe = f"cpe:2.3:a:{vendor}:{prod_name}:{ver if ver else '*'}:*:*:*:*:*:*:*"
                    
                    yield {
                        "ip": current_ip,
                        "port_id": int(elem.get("portid", 0)),
                        "protocol": elem.get("protocol", "tcp"),
                        "cpe": cpe,
                        "service_info": {"service": svc, "product": prod, "version": ver}
                    }
            elif event == "end" and elem.tag == "host":
                current_ip = None
                elem.clear()
    except Exception as e:
        log.error(f"XML Parsing Error: {e}")

# ---------------------------------------------------------------------------
# Intelligence Logic
# ---------------------------------------------------------------------------
def filter_vulnerabilities(raw_vulns: list, min_score: float) -> list:
    results, seen_cves = [], set()
    for item in raw_vulns:
        cve_block = item.get("cve", {})
        cve_id = cve_block.get("id")
        if not cve_id or cve_id in seen_cves: continue
            
        metrics = cve_block.get("metrics", {})
        score = 0.0
        for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if k in metrics:
                score = float(metrics[k][0].get("cvssData", {}).get("baseScore", 0.0))
                break
                
        if score < min_score: continue
        seen_cves.add(cve_id)

        severity = "CRITICAL" if score >= 9.0 else "HIGH" if score >= 7.0 else "MEDIUM" if score >= 4.0 else "LOW"
        refs = cve_block.get("references", [])
        ref_urls = [r.get("url", "") for r in refs]
        
        has_exploit = any("exploit" in r.lower() or "rapid7" in r.lower() for r in ref_urls)
        msf_module = next((re.search(r'/modules/([^?#]+)', u).group(1).replace(".html", "") 
                           for u in ref_urls if "rapid7.com/db/modules" in u and re.search(r'/modules/([^?#]+)', u)), None)
        
        desc_list = cve_block.get("descriptions", [])
        desc = next((d.get("value", "") for d in desc_list if isinstance(d, dict) and d.get("lang") == "en"), 
                    desc_list[0].get("value", "") if desc_list and isinstance(desc_list[0], dict) else "No description")

        results.append({"cve_id": cve_id, "score": score, "severity": severity, 
                        "has_exploit": has_exploit, "msf_module": msf_module, "description": desc})
    return sorted(results, key=lambda x: x["score"], reverse=True)

# ---------------------------------------------------------------------------
# Producer / Consumer Workers
# ---------------------------------------------------------------------------
async def worker_node(
    worker_id: int, 
    task_queue: asyncio.PriorityQueue, 
    result_queue: asyncio.Queue, 
    client: SharedNVDClient, 
    session: aiohttp.ClientSession, 
    min_score: float, 
    progress_cb: Callable
):
    while True:
        try:
            item: TaskItem = await task_queue.get()
            
            if item.cpe != "cpe:2.3:a:unknown:unknown:*:*:*:*:*:*:*:*":
                if progress_cb: progress_cb(f"[*] Worker-{worker_id} analyzing {item.ip}:{item.port_id}")
                
                raw_vulns = await client.fetch_cves(session, item.cpe)
                cves = filter_vulnerabilities(raw_vulns, min_score)
                
                if cves:
                    await result_queue.put({
                        "ip": item.ip,
                        "port_id": item.port_id,
                        "protocol": item.protocol,
                        "cpe": item.cpe,
                        "service": item.service_info["service"],
                        "cves": cves
                    })
            task_queue.task_done()
        except asyncio.CancelledError:
            break
        except Exception as e:
            log.error(f"Worker {worker_id} failed on {item.ip}:{item.port_id}: {e}")
            task_queue.task_done()

async def result_writer(result_queue: asyncio.Queue, jsonl_path: Path):
    """Incremental JSONL writer. Safe from pipeline crashes."""
    def _append(data: dict):
        with open(jsonl_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(data) + '\n')

    while True:
        try:
            result = await result_queue.get()
            if result is None: # Shutdown sentinel
                result_queue.task_done()
                break
            await asyncio.to_thread(_append, result)
            result_queue.task_done()
        except asyncio.CancelledError:
            break

# ---------------------------------------------------------------------------
# Main Orchestrator
# ---------------------------------------------------------------------------
async def run_pipeline(
    xml_path: str, 
    api_key: Optional[str] = None, 
    min_score: float = 7.0, 
    output_dir: str = "kamui_output", 
    cache_db: Optional[str] = None, 
    progress_cb: Optional[Callable] = None
) -> str:
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    
    jsonl_path = out_dir / f"intel_{int(time.time())}.jsonl"
    db_path = Path(cache_db) if cache_db else out_dir / "kamui_intel.db"
    
    cache = PersistentCacheDB(db_path)
    await cache.connect()
    client = SharedNVDClient(api_key, cache)
    
    task_queue = asyncio.PriorityQueue()
    result_queue = asyncio.Queue()
    
    # 1. Start Result Writer
    writer_task = asyncio.create_task(result_writer(result_queue, jsonl_path))
    
    # 2. Start Worker Pool
    async with aiohttp.ClientSession() as session:
        workers = [
            asyncio.create_task(worker_node(i, task_queue, result_queue, client, session, min_score, progress_cb))
            for i in range(WORKER_POOL_SIZE)
        ]
        
        # 3. Producer: Stream XML directly into Priority Queue
        for port_data in stream_nmap_xml(xml_path):
            priority = 1 if port_data["port_id"] in CRITICAL_PORTS else 10
            await task_queue.put(TaskItem(
                priority=priority,
                timestamp=time.time(),
                ip=port_data["ip"],
                port_id=port_data["port_id"],
                protocol=port_data["protocol"],
                cpe=port_data["cpe"],
                service_info=port_data["service_info"]
            ))
            
        # 4. Await Completion
        await task_queue.join()
        
        # 5. Shutdown Sequence
        for w in workers: w.cancel()
        await result_queue.put(None) 
        await writer_task
        await cache.close()
        
    return str(jsonl_path)