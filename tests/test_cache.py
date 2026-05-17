"""Unit tests for the in-memory TTL DecisionCache."""

from __future__ import annotations

import time
from unittest.mock import patch

from rugguard_sniper_bot.cache import DecisionCache


def test_cache_hit_within_ttl():
    c = DecisionCache(ttl_seconds=60)
    c.put("base", "0xABC", {"score": 12})
    assert c.get("base", "0xABC") == {"score": 12}


def test_cache_miss_after_ttl():
    c = DecisionCache(ttl_seconds=1)
    c.put("base", "0xABC", {"score": 12})
    with patch(
        "rugguard_sniper_bot.cache.time.monotonic",
        return_value=time.monotonic() + 100,
    ):
        assert c.get("base", "0xABC") is None


def test_cache_chain_normalization():
    c = DecisionCache(ttl_seconds=60)
    c.put("BASE", "0xABC", {"score": 1})
    assert c.get("base", "0xABC") == {"score": 1}
    assert c.get("base", "0xabc") is None
