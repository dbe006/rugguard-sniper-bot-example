"""Tests for the sniper bot loop. All hermetic — no LLM, no network."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from rugguard_sniper_bot import (
    DecisionCache,
    SniperDecision,
    evaluate_candidate,
    run_sniper,
)


def _canned(
    *,
    recommendation: str = "allow",
    score: int = 12,
    verdict: str = "safe",
    intended: float = 100.0,
) -> dict[str, Any]:
    if recommendation == "allow":
        cap = intended
    elif recommendation == "caution":
        cap = intended * 0.2
    else:
        cap = 0.0
    return {
        "scan_id": "t-01",
        "chain": "base",
        "contract": "0xABC",
        "policy_recommendation": recommendation,
        "risk_score": score,
        "verdict": verdict,
        "max_suggested_exposure_usd": cap,
        "reason": [],
        "key_fingerprint": "a0c71156d8747078",
    }


# --- evaluate_candidate ---


@pytest.mark.asyncio
async def test_evaluate_allow_returns_full_exposure():
    async def fake(*, url, json_body, **_kw):
        assert url.endswith("/v1/pretrade/check")
        return 200, _canned()

    with patch("rugguard_sniper_bot.bot.paid_post", new=fake):
        d = await evaluate_candidate(
            chain="base",
            contract="0xABC",
            intended_trade_usd=100.0,
            policy="balanced",
            private_key_hex="0x" + "ab" * 32,
            api_url="https://rugguard.redfleet.fr",
        )
    assert d.recommendation == "allow"
    assert d.executed_size_usd == 100.0
    assert d.risk_score == 12


@pytest.mark.asyncio
async def test_evaluate_caution_clamps_size():
    async def fake(*, url, json_body, **_kw):
        return 200, _canned(recommendation="caution", score=60, verdict="medium_risk")

    with patch("rugguard_sniper_bot.bot.paid_post", new=fake):
        d = await evaluate_candidate(
            chain="base",
            contract="0xABC",
            intended_trade_usd=100.0,
            policy="balanced",
            private_key_hex="0x" + "ab" * 32,
            api_url="https://rugguard.redfleet.fr",
        )
    assert d.recommendation == "caution"
    assert d.executed_size_usd == 20.0  # 20% of intended


@pytest.mark.asyncio
async def test_evaluate_block_zeros_size():
    async def fake(*, url, json_body, **_kw):
        return 200, _canned(recommendation="block", score=95, verdict="critical")

    with patch("rugguard_sniper_bot.bot.paid_post", new=fake):
        d = await evaluate_candidate(
            chain="base",
            contract="0xABC",
            intended_trade_usd=100.0,
            policy="balanced",
            private_key_hex="0x" + "ab" * 32,
            api_url="https://rugguard.redfleet.fr",
        )
    assert d.recommendation == "block"
    assert d.executed_size_usd == 0.0


@pytest.mark.asyncio
async def test_evaluate_payment_error_returns_error_decision():
    from rugguard_sniper_bot.x402_pay import X402PaymentError

    async def failing(*, url, json_body, **_kw):
        raise X402PaymentError("payment_rejected:PAYMENT_VERIFY_FAILED")

    with patch("rugguard_sniper_bot.bot.paid_post", new=failing):
        d = await evaluate_candidate(
            chain="base",
            contract="0xABC",
            intended_trade_usd=100.0,
            policy="balanced",
            private_key_hex="0x" + "ab" * 32,
            api_url="https://rugguard.redfleet.fr",
        )
    assert d.recommendation == "error"
    assert d.executed_size_usd == 0.0
    assert "payment_failed" in d.error


@pytest.mark.asyncio
async def test_evaluate_non_200_returns_error_decision():
    async def fake(*, url, json_body, **_kw):
        return 400, {"detail": {"code": "INVALID_POLICY"}}

    with patch("rugguard_sniper_bot.bot.paid_post", new=fake):
        d = await evaluate_candidate(
            chain="base",
            contract="0xABC",
            intended_trade_usd=100.0,
            policy="balanced",
            private_key_hex="0x" + "ab" * 32,
            api_url="https://rugguard.redfleet.fr",
        )
    assert d.recommendation == "error"
    assert "non_200" in d.error


@pytest.mark.asyncio
async def test_cache_hit_skips_payment():
    """Second evaluation for the same (chain, contract) inside the TTL
    window must NOT call paid_post."""
    cache = DecisionCache(ttl_seconds=300)
    calls: list[int] = []

    async def fake(*, url, json_body, **_kw):
        calls.append(1)
        return 200, _canned()

    with patch("rugguard_sniper_bot.bot.paid_post", new=fake):
        await evaluate_candidate(
            chain="base", contract="0xABC", intended_trade_usd=100.0, policy="balanced",
            private_key_hex="0x" + "ab" * 32, api_url="https://example", cache=cache,
        )
        await evaluate_candidate(
            chain="base", contract="0xABC", intended_trade_usd=100.0, policy="balanced",
            private_key_hex="0x" + "ab" * 32, api_url="https://example", cache=cache,
        )

    assert len(calls) == 1


# --- run_sniper aggregate flow ---


@pytest.mark.asyncio
async def test_run_sniper_aggregates_stats():
    """Run the bot over a mixed list and verify stats math."""
    responses = {
        "0xSAFE": _canned(recommendation="allow"),
        "0xMID": _canned(recommendation="caution", score=60, verdict="medium_risk"),
        "0xRUG": _canned(recommendation="block", score=95, verdict="critical"),
    }

    async def fake(*, url, json_body, **_kw):
        return 200, responses.get(json_body["contract"], _canned())

    with patch("rugguard_sniper_bot.bot.paid_post", new=fake):
        stats = await run_sniper(
            candidates=["0xSAFE", "0xMID", "0xRUG"],
            chain="base",
            intended_trade_usd=100.0,
            policy="balanced",
            private_key_hex="0x" + "ab" * 32,
            session_spend_cap_usd=10.0,
        )

    assert stats.candidates_evaluated == 3
    assert stats.candidates_executed == 2  # allow + caution
    assert stats.candidates_skipped == 1  # block
    assert stats.would_be_buy_total_usd == 300.0  # 3 * 100
    # allow=100 + caution=20 + block=0 = 120
    assert stats.actual_executed_total_usd == 120.0
    # v0.1.1: accounting is at per_call_max_usdc (default $0.02) not actual
    # $0.01, so 3 calls = $0.06. The upper-bound accounting is intentionally
    # conservative — guards against silent price drift on the server side.
    assert stats.rugguard_spend_usdc == pytest.approx(0.06, rel=1e-6)


@pytest.mark.asyncio
async def test_run_sniper_honors_session_spend_cap():
    """If the session cap is small enough to break mid-loop, run_sniper
    must stop before exceeding it, leaving later candidates unevaluated."""

    async def fake(*, url, json_body, **_kw):
        return 200, _canned()

    with patch("rugguard_sniper_bot.bot.paid_post", new=fake):
        # v0.1.1 upper-bound accounting at $0.02/call: cap of $0.05
        # allows iterations 1+2 (0.02, 0.04) and aborts before iteration 3
        # (would be 0.06 > 0.05). Older v0.1.0 test used $0.025 cap which
        # under the new accounting would only allow 1 candidate.
        stats = await run_sniper(
            candidates=[f"0x{i:040x}" for i in range(1, 6)],
            chain="base",
            intended_trade_usd=100.0,
            policy="balanced",
            private_key_hex="0x" + "ab" * 32,
            session_spend_cap_usd=0.05,
        )

    assert stats.candidates_evaluated == 2, (
        f"expected the bot to stop after 2 candidates due to session cap, "
        f"got {stats.candidates_evaluated}"
    )


# --- SniperDecision dataclass smoke ---


def test_sniper_decision_default_fields():
    d = SniperDecision(
        chain="base", contract="0xABC", intended_trade_usd=100.0, recommendation="block"
    )
    assert d.executed_size_usd == 0.0
    assert d.reason_codes == []
    assert d.signature_fingerprint is None
    assert d.error is None


# --- v0.1.1 security batch 1: https + per-call max + exception leak ---


@pytest.mark.asyncio
async def test_evaluate_rejects_plaintext_api_url():
    """Plaintext api_url → config_error before any payment attempt."""
    d = await evaluate_candidate(
        chain="base",
        contract="0xABC",
        intended_trade_usd=100.0,
        policy="balanced",
        private_key_hex="0x" + "ab" * 32,
        api_url="http://attacker.example",
    )
    assert d.recommendation == "error"
    assert "config_error" in d.error
    assert "https" in d.error.lower()


@pytest.mark.asyncio
async def test_evaluate_passes_max_amount_usdc_default_002():
    """v0.1.1: evaluate_candidate defaults max_amount_usdc to $0.02."""
    captured: dict = {}

    async def fake(*, url, json_body, private_key_hex, max_amount_usdc=None, **_kw):
        captured["max_amount_usdc"] = max_amount_usdc
        return 200, _canned()

    with patch("rugguard_sniper_bot.bot.paid_post", new=fake):
        await evaluate_candidate(
            chain="base",
            contract="0xABC",
            intended_trade_usd=100.0,
            policy="balanced",
            private_key_hex="0x" + "ab" * 32,
            api_url="https://rugguard.redfleet.fr",
        )

    assert captured["max_amount_usdc"] == 0.02


@pytest.mark.asyncio
async def test_evaluate_generic_exception_does_not_leak_str_exc():
    """v0.1.1 dropped `str(exc)` from the generic except branch to prevent
    a malformed private key (which eth_account echoes in ValueError) from
    landing in SniperDecision.error and getting logged."""
    secret_marker = "SECRET_KEY_LEAKED_VALUE_42"

    async def fake(*, url, json_body, **_kw):
        raise RuntimeError(f"this contains {secret_marker}")

    with patch("rugguard_sniper_bot.bot.paid_post", new=fake):
        d = await evaluate_candidate(
            chain="base",
            contract="0xABC",
            intended_trade_usd=100.0,
            policy="balanced",
            private_key_hex="0x" + "ab" * 32,
            api_url="https://rugguard.redfleet.fr",
        )

    assert d.recommendation == "error"
    # The exception class name is fine ; the *message* must not leak.
    assert "RuntimeError" in d.error
    assert secret_marker not in d.error, (
        "v0.1.1 regression: SniperDecision.error must not embed str(exc) — "
        "a malformed private key in eth_account.ValueError would leak the key."
    )


@pytest.mark.asyncio
async def test_run_sniper_session_cap_uses_per_call_max_upper_bound():
    """v0.1.1: cap accounting is at per_call_max_usdc (upper bound), not
    actual $0.01. Session cap = $0.05 with per_call_max=$0.02 should stop
    after 2 candidates (next would be 0.04 + 0.02 = 0.06 > 0.05)."""

    async def fake(*, url, json_body, **_kw):
        return 200, _canned()

    with patch("rugguard_sniper_bot.bot.paid_post", new=fake):
        stats = await run_sniper(
            candidates=[f"0x{i:040x}" for i in range(1, 6)],
            chain="base",
            intended_trade_usd=100.0,
            policy="balanced",
            private_key_hex="0x" + "ab" * 32,
            session_spend_cap_usd=0.05,
            per_call_max_usdc=0.02,
        )

    assert stats.candidates_evaluated == 2, (
        f"expected 2 candidates evaluated before cap, got {stats.candidates_evaluated}"
    )
