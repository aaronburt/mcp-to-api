import asyncio
import time
from collections import deque
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

from gateway.config import RateLimitSpec


class RateLimitExceeded(Exception):
    def __init__(self, scope: str, retry_after: float) -> None:
        super().__init__(f"Rate limit exceeded ({scope})")
        self.scope = scope
        self.retry_after = max(0.0, retry_after)


class ConcurrencyLimitTimeout(Exception):
    pass


class SlidingWindowLimiter:
    def __init__(self, clock: Callable[[], float] = time.monotonic, max_keys: int = 4096) -> None:
        self._clock = clock
        self._windows: dict[str, deque[float]] = {}
        self._max_keys = max_keys
        self._lock = asyncio.Lock()

    def _prune(self, dq: deque[float], cutoff: float) -> None:
        while dq and dq[0] <= cutoff:
            dq.popleft()

    def _check_unlocked(
        self,
        now: float,
        checks: list[tuple[str, str, RateLimitSpec]],
    ) -> None:
        for key, scope_label, spec in checks:
            dq = self._windows.get(key)
            if dq is not None:
                self._prune(dq, now - spec.window_seconds)
                if not dq:
                    del self._windows[key]
                    dq = None
            if dq is not None and len(dq) >= spec.limit:
                retry_after = (dq[0] + spec.window_seconds) - now
                raise RateLimitExceeded(scope_label, retry_after)

    async def check(
        self,
        checks: list[tuple[str, str, RateLimitSpec]],
    ) -> None:
        now = self._clock()
        async with self._lock:
            self._check_unlocked(now, checks)

    async def check_and_record(
        self,
        checks: list[tuple[str, str, RateLimitSpec]],
    ) -> None:
        now = self._clock()
        async with self._lock:
            self._check_unlocked(now, checks)
            for key, _, _ in checks:
                if key not in self._windows and len(self._windows) >= self._max_keys:
                    oldest_key = next(iter(self._windows))
                    del self._windows[oldest_key]
                self._windows.setdefault(key, deque()).append(now)


class ConcurrencyManager:
    def __init__(self, capacities: dict[str, int]) -> None:
        self._semaphores = {
            name: asyncio.Semaphore(cap) for name, cap in capacities.items()
        }

    @asynccontextmanager
    async def slot(self, service_name: str, wait_timeout: float) -> AsyncIterator[None]:
        sem = self._semaphores[service_name]
        try:
            await asyncio.wait_for(sem.acquire(), timeout=wait_timeout)
        except TimeoutError as exc:
            raise ConcurrencyLimitTimeout(
                f"Upstream '{service_name}' concurrency queue timed out"
            ) from exc
        try:
            yield
        finally:
            sem.release()
