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


# --- v0.1.2: verify=True signature verification path ---


@pytest.mark.asyncio
async def test_verify_true_without_signature_skips_check():
    """Unsigned deployment: verify=True is a no-op, normal happy path."""
    response = _canned()
    response["signature"] = None
    response["key_fingerprint"] = None

    async def fake(*, url, json_body, **_kw):
        return 200, response

    with patch("rugguard_sniper_bot.bot.paid_post", new=fake):
        d = await evaluate_candidate(
            chain="base",
            contract="0xABC",
            intended_trade_usd=100.0,
            policy="balanced",
            private_key_hex="0x" + "ab" * 32,
            api_url="https://rugguard.redfleet.fr",
            verify=True,
        )
    assert d.recommendation == "allow"


@pytest.mark.asyncio
async def test_verify_true_invalid_signature_routes_to_error():
    """Tampered signature → recommendation="error", NEVER allowed to buy."""
    response = _canned()
    response["signature"] = "VEVTVA=="  # garbage
    response["key_fingerprint"] = "deadbeef"

    async def fake_post(*, url, json_body, **_kw):
        return 200, response

    async def fake_pubkey(_api_url):
        import base64

        return base64.b64encode(b"\x00" * 32).decode()

    with (
        patch("rugguard_sniper_bot.bot.paid_post", new=fake_post),
        patch("rugguard_sniper_bot.bot._resolve_pubkey_for_verify", new=fake_pubkey),
    ):
        d = await evaluate_candidate(
            chain="base",
            contract="0xABC",
            intended_trade_usd=100.0,
            policy="balanced",
            private_key_hex="0x" + "ab" * 32,
            api_url="https://rugguard.redfleet.fr",
            verify=True,
        )

    assert d.recommendation == "error"
    assert d.executed_size_usd == 0.0
    assert "signature_invalid" in d.error.lower() or "fingerprint" in d.error.lower()


# --- v0.1.3 hardening: private key format + addresses-file caps ---


def test_validate_private_key_accepts_canonical_forms():
    """Both 64-char bare hex and 0x-prefixed 66-char hex pass validation."""
    from rugguard_sniper_bot.bot import _validate_private_key_format

    _validate_private_key_format("ab" * 32)  # bare
    _validate_private_key_format("0x" + "ab" * 32)  # 0x-prefixed
    _validate_private_key_format("0x" + "AB" * 32)  # mixed case


def test_validate_private_key_rejects_garbage():
    """Reject everything not matching the expected shape; never embed
    the bad value in the error message (defends against leaking secrets
    or partial secrets into logs)."""
    from rugguard_sniper_bot.bot import _validate_private_key_format

    bad_inputs = [
        "",
        "deadbeef",  # too short
        "ab" * 33,  # too long
        "0x" + "ab" * 31,  # 0x + 62 chars
        "zz" * 32,  # non-hex
        "ab" * 31 + "ZZ",  # ends non-hex
        None,
    ]
    for bad in bad_inputs:
        with pytest.raises(ValueError) as excinfo:
            _validate_private_key_format(bad)  # type: ignore[arg-type]
        # Verify the bad input never appears in the error text.
        if isinstance(bad, str) and bad:
            assert bad not in str(excinfo.value)


def test_load_addresses_rejects_oversize_file(tmp_path):
    """A 2 MB candidate file is refused before any line is parsed."""
    import argparse

    from rugguard_sniper_bot.bot import (
        MAX_ADDRESSES_FILE_BYTES,
        AddressesFileError,
        _load_addresses,
    )

    p = tmp_path / "huge.txt"
    # Write ~1.5 MB of "a"s in one blob — line-count is irrelevant; this
    # test exists specifically to verify the byte-size guard short-circuits
    # before any read.
    p.write_text("a" * (MAX_ADDRESSES_FILE_BYTES + 512_000))
    # Ensure the test setup actually overshoots the cap.
    assert p.stat().st_size > MAX_ADDRESSES_FILE_BYTES

    args = argparse.Namespace(addresses=None, addresses_file=str(p))
    with pytest.raises(AddressesFileError) as excinfo:
        _load_addresses(args)
    assert "max allowed" in str(excinfo.value)


def test_load_addresses_rejects_too_many_lines(tmp_path):
    """A file with >MAX_ADDRESSES_LINES rows is refused after counting."""
    import argparse

    from rugguard_sniper_bot.bot import (
        MAX_ADDRESSES_LINES,
        AddressesFileError,
        _load_addresses,
    )

    p = tmp_path / "many.txt"
    # Keep each line short so total size is under MAX_ADDRESSES_FILE_BYTES
    # and the failure is specifically the line-count cap.
    p.write_text(("0x" + "a" * 40 + "\n") * (MAX_ADDRESSES_LINES + 5))
    args = argparse.Namespace(addresses=None, addresses_file=str(p))
    with pytest.raises(AddressesFileError) as excinfo:
        _load_addresses(args)
    assert str(MAX_ADDRESSES_LINES) in str(excinfo.value)


def test_load_addresses_rejects_overlong_line(tmp_path):
    """A single 500-char line is refused — the file is clearly not a
    candidate list."""
    import argparse

    from rugguard_sniper_bot.bot import AddressesFileError, _load_addresses

    p = tmp_path / "bad.txt"
    p.write_text("0x" + "a" * 500 + "\n")
    args = argparse.Namespace(addresses=None, addresses_file=str(p))
    with pytest.raises(AddressesFileError) as excinfo:
        _load_addresses(args)
    assert "is not a list of token addresses" in str(excinfo.value)


def test_load_addresses_rejects_missing_path(tmp_path):
    """Nonexistent path → AddressesFileError (not bare FileNotFoundError)."""
    import argparse

    from rugguard_sniper_bot.bot import AddressesFileError, _load_addresses

    missing = tmp_path / "does-not-exist.txt"
    args = argparse.Namespace(addresses=None, addresses_file=str(missing))
    with pytest.raises(AddressesFileError) as excinfo:
        _load_addresses(args)
    assert "does not exist" in str(excinfo.value)


def test_load_addresses_rejects_directory(tmp_path):
    """A directory path is refused (caller probably meant a file inside)."""
    import argparse

    from rugguard_sniper_bot.bot import AddressesFileError, _load_addresses

    args = argparse.Namespace(addresses=None, addresses_file=str(tmp_path))
    with pytest.raises(AddressesFileError) as excinfo:
        _load_addresses(args)
    assert "not a regular file" in str(excinfo.value)


def test_load_addresses_accepts_normal_file(tmp_path):
    """Sanity check: a well-formed small file parses correctly with
    comments and blank lines stripped."""
    import argparse

    from rugguard_sniper_bot.bot import _load_addresses

    p = tmp_path / "good.txt"
    p.write_text(
        "# header comment\n"
        "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913\n"
        "\n"
        "  0x4ed4E862860beD51a9570b96d89aF5E1B0Efefed  \n"
        "# trailing comment\n"
    )
    args = argparse.Namespace(addresses=None, addresses_file=str(p))
    addrs = _load_addresses(args)
    assert addrs == [
        "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        "0x4ed4E862860beD51a9570b96d89aF5E1B0Efefed",
    ]
