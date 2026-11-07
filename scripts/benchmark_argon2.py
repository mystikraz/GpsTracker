from __future__ import annotations

import asyncio
import resource
import time

from fleet_tracker.auth_security import PasswordService


async def main() -> None:
    service = PasswordService(max_concurrency=2)
    started = time.perf_counter()
    await asyncio.gather(*(service.hash("benchmark password 12345") for _ in range(4)))
    print({
        "four_hash_seconds": round(time.perf_counter() - started, 3),
        "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "concurrency_limit": 2,
    })


asyncio.run(main())
