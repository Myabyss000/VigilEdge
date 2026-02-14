"""
ThreatLoom Firewall SDK — Drop this into your firewall project.

This is a lightweight async + sync client that sends logs from your firewall
to ThreatLoom's ingestion API and receives block/unblock commands.

Usage in your firewall:
    from threatloom_sdk import ThreatLoomClient

    client = ThreatLoomClient("http://localhost:8443", "admin", "changeme")
    client.send_log({
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "action": "BLOCKED",
        "attack_type": "SQLI",
        "http_method": "POST",
        "http_path": "/api/data",
        "http_status": 403,
    })
"""
import json
import logging
import time
from typing import Optional, Dict, Any, List
from threading import Thread
from queue import Queue, Empty

logger = logging.getLogger("threatloom_sdk")


class ThreatLoomClient:
    """
    Synchronous + async client for pushing firewall logs to ThreatLoom SOC.

    Features:
      - Auto-login with JWT token caching & refresh
      - Buffered batch sending (collects logs, flushes every N or every T seconds)
      - Fire-and-forget background thread so your firewall never blocks
      - Sync helper methods (no asyncio needed in your firewall)
    """

    def __init__(
        self,
        soc_url: str = "http://localhost:8443",
        username: str = "admin",
        password: str = "changeme",
        batch_size: int = 50,
        flush_interval: float = 5.0,
        timeout: float = 10.0,
    ):
        self.soc_url = soc_url.rstrip("/")
        self.username = username
        self.password = password
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.timeout = timeout

        self._token: Optional[str] = None
        self._token_expiry: float = 0
        self._queue: Queue = Queue()
        self._running = False
        self._thread: Optional[Thread] = None

        # Import httpx lazily so the SDK file stays lightweight
        try:
            import httpx
            self._httpx = httpx
        except ImportError:
            raise ImportError(
                "httpx is required: pip install httpx"
            )

    # ── Authentication ──────────────────────────────────────────────────

    def _login(self) -> str:
        """Authenticate and cache JWT token."""
        resp = self._httpx.post(
            f"{self.soc_url}/api/v1/users/login",
            json={"username": self.username, "password": self.password},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        self._token = data["access_token"]
        # Refresh 5 minutes before expiry (default 8h token)
        self._token_expiry = time.time() + (7.5 * 3600)
        logger.info("ThreatLoom SDK: authenticated successfully")
        return self._token

    def _get_token(self) -> str:
        if not self._token or time.time() >= self._token_expiry:
            return self._login()
        return self._token

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._get_token()}"}

    # ── Single log send (synchronous) ───────────────────────────────────

    def send_log(self, log: Dict[str, Any]) -> dict:
        """
        Send a single log entry to ThreatLoom (blocking).

        Args:
            log: dict with firewall log fields. Minimum: {"src_ip": "..."}
                 Full field list: src_ip, dst_ip, src_port, dst_port,
                 protocol, action, attack_type, severity, http_method,
                 http_path, http_status, user_agent, rule_id, raw_message

        Returns:
            {"status": "ingested", "log_id": 123}
        """
        resp = self._httpx.post(
            f"{self.soc_url}/api/v1/logs/ingest/json",
            json=log,
            headers=self._headers(),
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def send_syslog(self, raw_line: str) -> dict:
        """Send a raw syslog line to ThreatLoom."""
        resp = self._httpx.post(
            f"{self.soc_url}/api/v1/logs/ingest/syslog",
            json={"raw": raw_line},
            headers=self._headers(),
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def send_batch(self, logs: List[Dict[str, Any]]) -> dict:
        """Send a batch of JSON logs to ThreatLoom."""
        resp = self._httpx.post(
            f"{self.soc_url}/api/v1/logs/ingest/batch",
            json={"logs": logs},
            headers=self._headers(),
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    # ── Fire-and-forget background sender ───────────────────────────────

    def queue_log(self, log: Dict[str, Any]):
        """
        Queue a log for background sending (non-blocking).

        Call start_background() first. Logs are batched and flushed
        every `batch_size` entries or every `flush_interval` seconds.
        """
        self._queue.put(log)

    def start_background(self):
        """Start the background log sender thread."""
        if self._running:
            return
        self._running = True
        self._thread = Thread(target=self._background_loop, daemon=True)
        self._thread.start()
        logger.info("ThreatLoom SDK: background sender started")

    def stop_background(self):
        """Stop background sender, flushing remaining logs."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)
        logger.info("ThreatLoom SDK: background sender stopped")

    def _background_loop(self):
        buffer = []
        last_flush = time.time()

        while self._running or not self._queue.empty():
            try:
                log = self._queue.get(timeout=0.5)
                buffer.append(log)
            except Empty:
                pass

            elapsed = time.time() - last_flush
            if len(buffer) >= self.batch_size or (buffer and elapsed >= self.flush_interval):
                try:
                    self.send_batch(buffer)
                    logger.debug(f"Flushed {len(buffer)} logs to ThreatLoom")
                except Exception as e:
                    logger.error(f"Failed to flush logs: {e}")
                buffer.clear()
                last_flush = time.time()

        # Final flush
        if buffer:
            try:
                self.send_batch(buffer)
            except Exception:
                pass

    # ── Query active blocks (pull from SOC) ─────────────────────────────

    def get_active_blocks(self) -> List[dict]:
        """
        Pull the list of currently active automated responses from ThreatLoom.
        Your firewall can poll this to sync its blocklist.
        """
        resp = self._httpx.get(
            f"{self.soc_url}/api/v1/responses/active",
            headers=self._headers(),
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def check_ip_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked in ThreatLoom."""
        blocks = self.get_active_blocks()
        return any(b.get("target_ip") == ip for b in blocks)


# ── Async version (if your firewall is async) ──────────────────────────────

class AsyncThreatLoomClient:
    """Async version of the ThreatLoom client for async firewalls."""

    def __init__(
        self,
        soc_url: str = "http://localhost:8443",
        username: str = "admin",
        password: str = "changeme",
        timeout: float = 10.0,
    ):
        import httpx
        self.soc_url = soc_url.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout
        self._token: Optional[str] = None
        self._token_expiry: float = 0
        self._client = httpx.AsyncClient(timeout=timeout)

    async def _login(self) -> str:
        resp = await self._client.post(
            f"{self.soc_url}/api/v1/users/login",
            json={"username": self.username, "password": self.password},
        )
        resp.raise_for_status()
        data = resp.json()
        self._token = data["access_token"]
        self._token_expiry = time.time() + (7.5 * 3600)
        return self._token

    async def _get_token(self) -> str:
        if not self._token or time.time() >= self._token_expiry:
            return await self._login()
        return self._token

    async def _headers(self) -> dict:
        return {"Authorization": f"Bearer {await self._get_token()}"}

    async def send_log(self, log: Dict[str, Any]) -> dict:
        resp = await self._client.post(
            f"{self.soc_url}/api/v1/logs/ingest/json",
            json=log,
            headers=await self._headers(),
        )
        resp.raise_for_status()
        return resp.json()

    async def send_batch(self, logs: List[Dict[str, Any]]) -> dict:
        resp = await self._client.post(
            f"{self.soc_url}/api/v1/logs/ingest/batch",
            json={"logs": logs},
            headers=await self._headers(),
        )
        resp.raise_for_status()
        return resp.json()

    async def get_active_blocks(self) -> List[dict]:
        resp = await self._client.get(
            f"{self.soc_url}/api/v1/responses/active",
            headers=await self._headers(),
        )
        resp.raise_for_status()
        return resp.json()

    async def close(self):
        await self._client.aclose()
