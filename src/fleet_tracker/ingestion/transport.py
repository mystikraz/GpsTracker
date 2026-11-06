"""Async TCP transport around the pure JT/T 808 message processor."""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from time import monotonic

from fleet_tracker.protocol.jt808 import FrameStreamParser, FrameTooLarge

from .processor import ConnectionState, MessageProcessor

logger = logging.getLogger("fleet_tracker.transport")


@dataclass(slots=True)
class _IpState:
    attempts: deque[float] = field(default_factory=deque)
    active: int = 0


class ConnectionLimiter:
    """Bound connection count and per-IP attempts without a new service."""

    def __init__(
        self,
        *,
        max_connections: int = 256,
        max_connections_per_ip: int = 8,
        attempts_per_minute: int = 20,
    ) -> None:
        self.max_connections = max_connections
        self.max_connections_per_ip = max_connections_per_ip
        self.attempts_per_minute = attempts_per_minute
        self._total_active = 0
        self._ips: dict[str, _IpState] = defaultdict(_IpState)
        self._lock = asyncio.Lock()

    async def acquire(self, ip: str) -> bool:
        now = monotonic()
        async with self._lock:
            state = self._ips[ip]
            while state.attempts and state.attempts[0] <= now - 60:
                state.attempts.popleft()
            if (
                self._total_active >= self.max_connections
                or state.active >= self.max_connections_per_ip
                or len(state.attempts) >= self.attempts_per_minute
            ):
                return False
            state.attempts.append(now)
            state.active += 1
            self._total_active += 1
            return True

    async def release(self, ip: str) -> None:
        async with self._lock:
            state = self._ips.get(ip)
            if state is None:
                return
            state.active = max(0, state.active - 1)
            self._total_active = max(0, self._total_active - 1)
            if state.active == 0 and not state.attempts:
                self._ips.pop(ip, None)


async def serve_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    processor: MessageProcessor,
    *,
    limiter: ConnectionLimiter | None = None,
    max_frame_size: int = 4096,
    max_buffer_size: int = 8192,
    idle_timeout_seconds: int = 180,
) -> None:
    peer = writer.get_extra_info("peername")
    ip = str(peer[0]) if isinstance(peer, tuple) and peer else "unknown"
    acquired = await limiter.acquire(ip) if limiter is not None else True
    if not acquired:
        writer.close()
        await writer.wait_closed()
        return

    parser = FrameStreamParser(max_frame_size=max_frame_size, max_buffer_size=max_buffer_size)
    state = ConnectionState()

    async def close_replaced_connection() -> None:
        writer.close()
        await writer.wait_closed()

    state.close_callback = close_replaced_connection
    try:
        while True:
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=idle_timeout_seconds)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            try:
                frames = parser.feed(chunk)
            except FrameTooLarge:
                break
            for frame in frames:
                try:
                    result = await processor.process(frame, state, source_ip=ip)
                except Exception:
                    # Persistence is the commit point. Do not emit an ACK when it fails.
                    logger.error(
                        "message_persistence_failed source_ip=%s terminal_id=%s message_id=0x%04x",
                        ip,
                        frame.header.terminal_id,
                        frame.header.message_id,
                    )
                    return
                if result.accepted:
                    logger.info(
                        "ingestion_message_accepted source_ip=%s terminal_id=%s "
                        "message_id=0x%04x parser_status=%s stored_positions=%s",
                        ip,
                        frame.header.terminal_id,
                        frame.header.message_id,
                        result.parser_status,
                        result.stored_positions,
                    )
                for response in result.responses:
                    writer.write(response)
                if result.responses:
                    await writer.drain()
                if result.close_connection:
                    return
    finally:
        if processor.connection_registry is not None:
            processor.connection_registry.release(state)
        if limiter is not None:
            await limiter.release(ip)
        writer.close()
        await writer.wait_closed()
