"""Per-process TTL cache for pre-trade decisions.

Avoids paying for the same (chain, contract) twice inside the cache window.
Default TTL: 5 minutes, matching RugGuard's server-side /v1/scan cache so
the agent never sees a fresher verdict by skipping the cache.

Not thread-safe. For multi-worker runtimes use a shared cache (Redis, etc.).
The API surface is intentionally simple to swap.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class _CacheEntry:
    value: dict[str, Any]
    expires_at: float


@dataclass
class DecisionCache:
    """In-memory TTL cache keyed by (chain, contract).

    Usage:
        cache = DecisionCache(ttl_seconds=300)
        cached = cache.get("base", "0xABC")
        if cached is None:
            result = await pretrade_check_async(...)
            cache.put("base", "0xABC", result)
    """

    ttl_seconds: float = 300.0
    _store: dict[tuple[str, str], _CacheEntry] = field(default_factory=dict)

    def _key(self, chain: str, contract: str) -> tuple[str, str]:
        # Normalize: chain lowercased, contract case-preserved (Solana base58
        # is case-sensitive ; EVM checksums are cosmetic, but contracts are
        # compared verbatim downstream so we don't mutate).
        return (chain.lower(), contract)

    def get(self, chain: str, contract: str) -> dict[str, Any] | None:
        entry = self._store.get(self._key(chain, contract))
        if entry is None:
            return None
        if time.monotonic() >= entry.expires_at:
            del self._store[self._key(chain, contract)]
            return None
        return entry.value

    def put(self, chain: str, contract: str, value: dict[str, Any]) -> None:
        self._store[self._key(chain, contract)] = _CacheEntry(
            value=value,
            expires_at=time.monotonic() + self.ttl_seconds,
        )

    def clear(self) -> None:
        self._store.clear()

    def __len__(self) -> int:
        return len(self._store)
