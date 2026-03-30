"""
kamui_bridge.py
===============
Enterprise-grade Nmap bridge.
Features: Semantic argument validation, isolated semaphore scopes,
SQLite metrics persistence, and graceful shutdown handlers.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Callable, List, Optional, Awaitable
from dataclasses import dataclass, asdict, field

# ---------------------------------------------------------------------------
# Logging & Telemetry
# ---------------------------------------------------------------------------
class ScanLogFilter(logging.Filter):
    def filter(self, record):
        if not hasattr(record, 'scan_id'): record.scan_id = 'SYSTEM'
        return True

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [%(scan_id)s] %(message)s")
base_log = logging.getLogger("kamui.bridge")
base_log.addFilter(ScanLogFilter())

@dataclass
class ExecutionMetrics:
    scan_id: str
    target: str = ""
    status: str = "PENDING"
    nmap_duration_sec: float = 0.0
    pipeline_duration_sec: float = 0.0
    total_duration_sec: float = 0.0
    error_msg: str = ""
    timestamp: float = field(default_factory=time.time)

class MetricsDB:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_metrics (
                    scan_id TEXT PRIMARY KEY, target TEXT, status TEXT,
                    nmap_duration_sec REAL, pipeline_duration_sec REAL,
                    total_duration_sec REAL, error_msg TEXT, timestamp REAL
                )
            """)
            
    def record(self, metrics: ExecutionMetrics):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("INSERT OR REPLACE INTO scan_metrics VALUES (?, ?, ?, ?, ?, ?, ?, ?)", tuple(asdict(metrics).values()))
        except Exception as e:
            base_log.error(f"Failed to record metrics: {e}")

# ---------------------------------------------------------------------------
# Security: Semantic Command Whitelisting
# ---------------------------------------------------------------------------
class CommandValidator:
    ALLOWED_FLAGS = {"-sS", "-sT", "-sU", "-sV", "-O", "-Pn", "-n", "--top-ports", "-T0", "-T1", "-T2", "-T3", "-T4", "-T5", "-A", "-v", "-vv"}
    HOSTNAME_REGEX = re.compile(r'^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]))*$')

    @classmethod
    def _is_valid_target(cls, token: str) -> bool:
        try:
            ipaddress.ip_network(token, strict=False)
            return True
        except ValueError:
            return bool(cls.HOSTNAME_REGEX.match(token))

    @classmethod
    def _is_valid_port_spec(cls, token: str) -> bool:
        val = token[2:] if token.startswith("-p") else token
        if not val: return False
        for part in val.split(','):
            bounds = part.split('-')
            if len(bounds) > 2: return False
            for b in bounds:
                if not b: continue
                try:
                    if not (1 <= int(b) <= 65535): return False
                except ValueError: return False
        return True

    @classmethod
    def sanitize(cls, cmd_list: List[str]) -> List[str]:
        if not cmd_list or cmd_list[0] != "nmap": raise ValueError("Command must initiate with 'nmap'")
        safe_cmd = ["nmap"]
        i = 1
        while i < len(cmd_list):
            token = cmd_list[i]
            if token in cls.ALLOWED_FLAGS: safe_cmd.append(token)
            elif token.startswith("-p"):
                if not cls._is_valid_port_spec(token): raise ValueError(f"Invalid port spec: {token}")
                safe_cmd.append(token)
            elif token == "-p":
                if i + 1 >= len(cmd_list) or not cls._is_valid_port_spec(cmd_list[i+1]): raise ValueError("Invalid port spec after -p")
                safe_cmd.extend([token, cmd_list[i+1]])
                i += 1
            elif cls._is_valid_target(token): safe_cmd.append(token)
            else: raise ValueError(f"Security Policy Violation: Unrecognized/invalid argument '{token}'")
            i += 1
        return safe_cmd

# ---------------------------------------------------------------------------
# Execution State Management
# ---------------------------------------------------------------------------
class ScanTask:
    def __init__(self, task: asyncio.Task, xml_path: Path):
        self._task = task
        self._xml_path = xml_path
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._proc_ready = asyncio.Event()
        self.is_cancelled = False

    def attach_process(self, proc: asyncio.subprocess.Process):
        self._proc = proc
        self._proc_ready.set()

    async def cancel(self, logger: logging.LoggerAdapter):
        self.is_cancelled = True
        try: await asyncio.wait_for(self._proc_ready.wait(), timeout=2.0)
        except asyncio.TimeoutError: logger.warning("Cancel requested, but process never attached.")
            
        if self._proc and self._proc.returncode is None:
            self._proc.terminate()
            try: await asyncio.wait_for(self._proc.wait(), timeout=3.0)
            except asyncio.TimeoutError:
                self._proc.kill()
                await self._proc.wait()
        if not self._task.done(): self._task.cancel()

# ---------------------------------------------------------------------------
# The Asynchronous Bridge
# ---------------------------------------------------------------------------
class AsyncKamuiBridge:
    def __init__(self, pipeline_func: Callable[[str, Any], Awaitable[dict]], api_key: Optional[str] = None, 
                 min_score: float = 7.0, output_dir: str = "kamui_output", scan_timeout: int = 1800, max_concurrent_scans: int = 3):
        self.pipeline_func = pipeline_func
        self.api_key = api_key
        self.min_score = min_score
        self.output_dir = Path(output_dir)
        self.scan_timeout = scan_timeout
        self.scan_semaphore = asyncio.Semaphore(max_concurrent_scans)
        
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "errors").mkdir(exist_ok=True)
        self.metrics_db = MetricsDB(self.output_dir / "kamui_metrics.db")
        self._active_tasks: List[ScanTask] = []

    async def shutdown(self):
        tasks = [t.cancel(logging.LoggerAdapter(base_log, {"scan_id": "SHUTDOWN"})) for t in self._active_tasks]
        if tasks: await asyncio.gather(*tasks, return_exceptions=True)

    async def _output_consumer(self, queue: asyncio.Queue, callback: Callable[[str], None], logger: logging.LoggerAdapter):
        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=1.0)
                if msg is None: break
                callback(msg)
            except asyncio.TimeoutError: continue 
            except Exception as e: logger.error(f"UI Callback failed: {e}")

    async def _stream_reader(self, stream: asyncio.StreamReader, queue: asyncio.Queue, task_state: ScanTask):
        while not task_state.is_cancelled:
            try:
                line = await stream.readline()
                if not line: break
                decoded = line.decode('utf-8', errors='replace').strip()
                if decoded:
                    try: queue.put_nowait(decoded)
                    except asyncio.QueueFull: pass
            except asyncio.CancelledError: break

    def _safe_enqueue(self, queue: asyncio.Queue, msg: str):
        try: queue.put_nowait(msg)
        except asyncio.QueueFull: pass

    async def _execute_scan(self, scan_id: str, xml_path: Path, cmd_list: List[str], 
                            output_cb: Optional[Callable], complete_cb: Optional[Callable], error_cb: Optional[Callable], task_state: ScanTask):
        logger = logging.LoggerAdapter(base_log, {"scan_id": scan_id})
        metrics = ExecutionMetrics(scan_id=scan_id, target=cmd_list[-1] if cmd_list else "unknown")
        t_start_total = time.perf_counter()
        
        output_queue = asyncio.Queue(maxsize=1000)
        consumer_task = asyncio.create_task(self._output_consumer(output_queue, output_cb, logger)) if output_cb else None
        if output_cb: self._safe_enqueue(output_queue, f"[*] Starting Scan ID: {scan_id}")

        nmap_success = False

        async with self.scan_semaphore:
            try:
                safe_cmd = CommandValidator.sanitize(cmd_list)
                final_cmd = safe_cmd + ["-oX", str(xml_path)]

                t_start_nmap = time.perf_counter()
                proc = await asyncio.create_subprocess_exec(*final_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
                task_state.attach_process(proc)

                reader_task = asyncio.create_task(self._stream_reader(proc.stdout, output_queue, task_state))
                await asyncio.wait_for(proc.wait(), timeout=self.scan_timeout)
                await reader_task 
                metrics.nmap_duration_sec = time.perf_counter() - t_start_nmap

                if task_state.is_cancelled:
                    self._safe_enqueue(output_queue, "[!] Scan was cancelled by user.")
                    metrics.status = "CANCELLED"
                elif proc.returncode != 0: raise RuntimeError(f"Nmap exited abnormally with code {proc.returncode}")
                elif not xml_path.exists(): raise FileNotFoundError("Nmap completed but XML output is missing.")
                else: nmap_success = True

            except asyncio.TimeoutError:
                metrics.status, metrics.error_msg = "TIMEOUT", "Global timeout exceeded"
                if error_cb: error_cb(metrics.error_msg)
                await task_state.cancel(logger)
            except asyncio.CancelledError:
                metrics.status = "CANCELLED"
            except Exception as e:
                metrics.status, metrics.error_msg = "FAILED", str(e)
                if error_cb: error_cb(f"Execution Error: {str(e)}")

        if nmap_success and not task_state.is_cancelled:
            self._safe_enqueue(output_queue, "\n[+] Nmap complete. Releasing lock and passing to Pipeline...")
            t_start_pipeline = time.perf_counter()
            try:
                from nmap_intel import run_pipeline
                results = await self.pipeline_func(
                    xml_path=str(xml_path), api_key=self.api_key, min_score=self.min_score,
                    output_dir=str(self.output_dir), progress_cb=lambda m: self._safe_enqueue(output_queue, m) if output_cb else None
                )
                metrics.pipeline_duration_sec = time.perf_counter() - t_start_pipeline
                metrics.status = "SUCCESS"
                if complete_cb: complete_cb(results)
            except Exception as e:
                metrics.status, metrics.error_msg = "PIPELINE_FAILED", str(e)
                if error_cb: error_cb(f"Pipeline Error: {str(e)}")

        metrics.total_duration_sec = time.perf_counter() - t_start_total
        self.metrics_db.record(metrics)
        
        if consumer_task:
            await output_queue.put(None) 
            await consumer_task
            
        if xml_path.exists():
            if metrics.status in ("SUCCESS", "CANCELLED"):
                try: xml_path.unlink()
                except OSError: pass
            else:
                try: xml_path.rename(self.output_dir / "errors" / f"failed_{scan_id}.xml")
                except OSError: pass

        if task_state in self._active_tasks: self._active_tasks.remove(task_state)

    def run_scan(self, cmd_list: List[str], output_cb: Optional[Callable] = None, complete_cb: Optional[Callable] = None, error_cb: Optional[Callable] = None) -> ScanTask:
        scan_id = uuid.uuid4().hex[:8]
        xml_path = self.output_dir / f"scan_{scan_id}.xml"
        loop = asyncio.get_running_loop()
        scan_task = ScanTask(loop.create_future(), xml_path)
        self._active_tasks.append(scan_task)
        scan_task._task = asyncio.create_task(self._execute_scan(scan_id, xml_path, cmd_list, output_cb, complete_cb, error_cb, scan_task))
        return scan_task