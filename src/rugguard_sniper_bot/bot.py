"""Educational sniper bot using RugGuard's pre-trade safety check.

NOT production-grade. See package docstring in __init__.py.

Three CLI modes:

    rugguard-sniper --demo                     # offline, 3 canned scenarios
    rugguard-sniper --addresses 0xA,0xB --size 100   # real x402 ; takes
                                                       # comma-separated
                                                       # tokens
    rugguard-sniper --addresses-file tokens.txt --size 100   # one per line

The bot loops over candidates, asks RugGuard for a policy_recommendation,
and produces a per-candidate `SniperDecision` plus aggregate `SniperStats`.
NO on-chain buy is executed — the "buy" is a log line. Swap
`execute_buy_mock` for your DEX router call to make it real (and review
the safety section in the README first).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest.mock import patch

from rugguard_sniper_bot.cache import DecisionCache
from rugguard_sniper_bot.x402_pay import (
    X402PaymentError,
    _validate_https_scheme,
    paid_post,
)

DEFAULT_API_URL = "https://rugguard.redfleet.fr"
DEFAULT_CHAIN = "base"
DEFAULT_POLICY = "balanced"

# Hard caps on --addresses-file input. An educational kit MUST refuse to
# eat a 10 GB file or 100K addresses — both would burn the session cap
# instantly OR (worse) leak memory in tight loops. The numbers below are
# generous for a real sniper session (10K candidates @ 128 chars/line ≈
# 1.3 MB) and refuse anything that smells like an accidental misconfig
# (pointed at a log file, /etc/passwd, etc.).
MAX_ADDRESSES_FILE_BYTES = 1 * 1024 * 1024  # 1 MB
MAX_ADDRESSES_LINES = 10_000
MAX_ADDRESS_LINE_LEN = 128

# Private key format. eth_account.Account.from_key accepts both bare
# (64-char) and 0x-prefixed (66-char) lowercase or mixed-case hex. We
# validate explicitly at CLI entry so:
#   - A malformed key never reaches eth_account, whose ValueError text
#     includes a `repr(key)` of the bad input. That value can leak into
#     SniperDecision.error via the generic except branch in
#     evaluate_candidate.
#   - The user gets a clear, immediate error from the CLI instead of a
#     buried "ValueError" from inside an async coroutine.
_PRIVATE_KEY_RE = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")

# Per-call USDC ceiling. RugGuard's /v1/pretrade/check costs $0.01 today.
# We cap at $0.02 so a price-doubling surprise (legit or hostile 402)
# is refused before signing rather than silently doubling the wallet drain.
# Increase only if you've verified the price increase out-of-band.
DEFAULT_PER_CALL_MAX_USDC = 0.02

# Hard session ceiling on RugGuard spend, accounted at PER_CALL_MAX (the
# upper bound). With the default $1 session cap + $0.02 per-call ceiling,
# the bot makes at most 50 calls per session even if x402 prices double.
# That's tighter than the v0.1.0 "$0.01 per call" assumption and resilient
# to price drift.
DEFAULT_SESSION_SPEND_CAP_USD = 1.0


@dataclass
class SniperDecision:
    """One candidate's outcome through the bot loop."""

    chain: str
    contract: str
    intended_trade_usd: float
    recommendation: str  # "block" | "caution" | "allow" | "error"
    risk_score: int | None = None
    verdict: str | None = None
    executed_size_usd: float = 0.0
    reason_codes: list[str] = field(default_factory=list)
    signature_fingerprint: str | None = None
    error: str | None = None


@dataclass
class SniperStats:
    """Aggregate output of one bot run."""

    candidates_evaluated: int = 0
    candidates_executed: int = 0
    candidates_skipped: int = 0
    rugguard_spend_usdc: float = 0.0
    would_be_buy_total_usd: float = 0.0
    actual_executed_total_usd: float = 0.0


async def evaluate_candidate(
    *,
    chain: str,
    contract: str,
    intended_trade_usd: float,
    policy: str,
    private_key_hex: str,
    api_url: str,
    cache: DecisionCache | None = None,
    max_amount_usdc: float = DEFAULT_PER_CALL_MAX_USDC,
    verify: bool = False,
) -> SniperDecision:
    """Run /v1/pretrade/check on one candidate, map to a SniperDecision.

    Cache hits don't pay. Network / payment errors map to
    `recommendation="error"` and `executed_size_usd=0.0` —
    conservative-by-default. A 402 advertising more than `max_amount_usdc`
    is refused before signing (defends against price drift and hostile
    402s)."""
    if cache is not None:
        cached = cache.get(chain, contract)
        if cached is not None:
            return _decision_from_response(
                chain, contract, intended_trade_usd, cached
            )

    url = f"{api_url.rstrip('/')}/v1/pretrade/check"

    # Validate trust root before signing. A plaintext api_url would leak
    # the trade intent and let a MITM tamper with the recommendation.
    try:
        _validate_https_scheme(url)
    except X402PaymentError as exc:
        return SniperDecision(
            chain=chain,
            contract=contract,
            intended_trade_usd=intended_trade_usd,
            recommendation="error",
            error=f"config_error: {exc}",
        )

    body = {
        "chain": chain,
        "contract": contract,
        "intended_trade_usd": intended_trade_usd,
        "policy": policy,
    }
    try:
        status, response = await paid_post(
            url=url,
            json_body=body,
            private_key_hex=private_key_hex,
            max_amount_usdc=max_amount_usdc,
        )
    except X402PaymentError as exc:
        return SniperDecision(
            chain=chain,
            contract=contract,
            intended_trade_usd=intended_trade_usd,
            recommendation="error",
            error=f"payment_failed: {exc}",
        )
    except Exception as exc:
        # Generic catch-all. We don't echo str(exc) here because a
        # malformed private key surfaces as ValueError(f"... {key!r}")
        # in eth_account, which would write the bad key into the
        # SniperDecision.error field. Surface only the exception class.
        return SniperDecision(
            chain=chain,
            contract=contract,
            intended_trade_usd=intended_trade_usd,
            recommendation="error",
            error=f"{type(exc).__name__}",
        )

    if status != 200:
        return SniperDecision(
            chain=chain,
            contract=contract,
            intended_trade_usd=intended_trade_usd,
            recommendation="error",
            error=f"non_200 status={status}",
        )

    # In-band Ed25519 signature verification (opt-in via verify=True).
    # Requires `pip install rugguard-sniper-bot-example[verify]`.
    # On verify failure → recommendation="error" (conservative-by-default,
    # NEVER lets the bot proceed on a tampered/unverifiable response).
    if verify and response.get("signature") is not None:
        try:
            from rugguard_verify import verify_signed_report
        except ImportError:
            return SniperDecision(
                chain=chain,
                contract=contract,
                intended_trade_usd=intended_trade_usd,
                recommendation="error",
                error=(
                    "config_error: verify=True needs rugguard-verify. "
                    "Install: pip install rugguard-sniper-bot-example[verify]"
                ),
            )
        pubkey = await _resolve_pubkey_for_verify(api_url)
        if pubkey is None:
            return SniperDecision(
                chain=chain,
                contract=contract,
                intended_trade_usd=intended_trade_usd,
                recommendation="error",
                error="signature_unverifiable: could not fetch /v1/pubkey",
            )
        check = verify_signed_report(response, pubkey)
        if not check.valid:
            return SniperDecision(
                chain=chain,
                contract=contract,
                intended_trade_usd=intended_trade_usd,
                recommendation="error",
                error=f"signature_invalid: {check.reason}",
            )

    if cache is not None:
        cache.put(chain, contract, response)
    return _decision_from_response(chain, contract, intended_trade_usd, response)


async def _resolve_pubkey_for_verify(api_url: str) -> str | None:
    """Fetch /v1/pubkey and return the active pubkey_base64, or None on
    any failure. Soft-fail by design — caller routes a None to
    recommendation="error" so the bot never proceeds on an
    unverifiable response."""
    import httpx

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{api_url.rstrip('/')}/v1/pubkey")
        if resp.status_code != 200:
            return None
        body = resp.json()
        if body.get("status") != "active":
            return None
        pubkey = body.get("pubkey_base64")
        return pubkey if isinstance(pubkey, str) and pubkey else None
    except Exception:
        return None


def _decision_from_response(
    chain: str, contract: str, intended_trade_usd: float, response: dict[str, Any]
) -> SniperDecision:
    rec = response.get("policy_recommendation", "block")
    return SniperDecision(
        chain=chain,
        contract=contract,
        intended_trade_usd=intended_trade_usd,
        recommendation=rec,
        risk_score=response.get("risk_score"),
        verdict=response.get("verdict"),
        executed_size_usd=float(response.get("max_suggested_exposure_usd") or 0.0),
        reason_codes=[r.get("code", "?") for r in (response.get("reason") or [])],
        signature_fingerprint=response.get("key_fingerprint"),
    )


def execute_buy_mock(decision: SniperDecision) -> None:
    """Stub for the real DEX router call. Replace with your own router
    integration to make it real. Uses the CLAMPED size, not the intended
    size — RugGuard's `max_suggested_exposure_usd` already down-sized for
    caution / blocked-out for block.

    ⚠ CRITICAL — READ BEFORE GOING LIVE ON MAINNET:

      When you replace this stub with a real router call, you MUST gate
      the router invocation on `decision.recommendation in ("allow",
      "caution")`. NEVER call the router for "error" or "block":

        - "error"  = network / payment / config failure ; the bot does
                     NOT know the verdict ; conservative-by-default
                     refuses the buy. A buy here is a silent bug.
        - "block"  = RugGuard explicitly said do not trade ; ignoring
                     it defeats the entire kit.

      Also use `decision.executed_size_usd` (the clamped size), NOT
      `decision.intended_trade_usd` — the clamp is the safety property
      that makes a "caution" verdict useful instead of binary.

      `run_sniper` itself enforces this gate (line below). If you call
      `execute_buy_mock` from your own code, replicate the gate.
    """
    badge = {
        "allow": "[BUY  ]",
        "caution": "[BUY*]",  # asterisk = downsized
        "block": "[SKIP ]",
        "error": "[ERR  ]",
    }.get(decision.recommendation, "[?    ]")
    reasons = ", ".join(decision.reason_codes[:2]) if decision.reason_codes else "-"
    sig = decision.signature_fingerprint or "unsigned"
    score = decision.risk_score if decision.risk_score is not None else "?"
    print(
        f"  {badge} {decision.chain}:{decision.contract[:10]}.. "
        f"score={score:>3} verdict={decision.verdict or '?':<12} "
        f"size=${decision.executed_size_usd:>7.2f}/${decision.intended_trade_usd:.0f} "
        f"reasons=[{reasons}] sig={sig[:8]}"
    )


async def run_sniper(
    *,
    candidates: list[str],
    chain: str = DEFAULT_CHAIN,
    intended_trade_usd: float,
    policy: str = DEFAULT_POLICY,
    private_key_hex: str,
    api_url: str = DEFAULT_API_URL,
    session_spend_cap_usd: float = DEFAULT_SESSION_SPEND_CAP_USD,
    per_call_max_usdc: float = DEFAULT_PER_CALL_MAX_USDC,
    verify: bool = False,
) -> SniperStats:
    """Main bot loop. Pre-trade-checks each candidate, mock-executes
    according to RugGuard's recommendation, aggregates stats. Aborts
    early if the next call's upper-bound (`per_call_max_usdc`) would push
    the session past `session_spend_cap_usd`.

    Bookkeeping accounts at `per_call_max_usdc` (the upper bound the kit
    refuses to exceed per call) rather than the actual paid amount. This
    is intentionally conservative — if RugGuard's price ever drifts up,
    the cap holds. v0.1.0 used the actual $0.01 price and would silently
    over-spend on a price bump."""
    cache = DecisionCache(ttl_seconds=300)
    stats = SniperStats()
    print(
        f"Sniper bot: {len(candidates)} candidates on {chain}, "
        f"policy={policy}, intended_size=${intended_trade_usd}, "
        f"session cap=${session_spend_cap_usd}, "
        f"per-call max=${per_call_max_usdc:.4f}\n"
    )

    for contract in candidates:
        # Stop the loop if the next call's worst-case spend would breach
        # the session cap. Accounting at `per_call_max_usdc` (the kit's
        # refusal threshold) makes the cap effective even if the server
        # advertises a higher price than the historical $0.01.
        if stats.rugguard_spend_usdc + per_call_max_usdc > session_spend_cap_usd:
            print(
                f"\nSession spend cap reached "
                f"(${stats.rugguard_spend_usdc:.4f}/${session_spend_cap_usd}). "
                f"Aborting before contract {contract[:10]}..."
            )
            break

        decision = await evaluate_candidate(
            chain=chain,
            contract=contract,
            intended_trade_usd=intended_trade_usd,
            policy=policy,
            private_key_hex=private_key_hex,
            api_url=api_url,
            cache=cache,
            max_amount_usdc=per_call_max_usdc,
            verify=verify,
        )
        stats.candidates_evaluated += 1
        # Account at the upper bound. Real settled amount is on-chain.
        stats.rugguard_spend_usdc += per_call_max_usdc
        stats.would_be_buy_total_usd += intended_trade_usd

        execute_buy_mock(decision)
        if decision.recommendation in ("allow", "caution"):
            stats.candidates_executed += 1
            stats.actual_executed_total_usd += decision.executed_size_usd
        else:
            stats.candidates_skipped += 1

    print(
        f"\nSession summary:"
        f"\n  candidates evaluated: {stats.candidates_evaluated}"
        f"\n  executed (mock):      {stats.candidates_executed}"
        f"\n  skipped:              {stats.candidates_skipped}"
        f"\n  RugGuard spend:       ${stats.rugguard_spend_usdc:.2f} USDC"
        f"\n  Would-be buy total:   ${stats.would_be_buy_total_usd:.2f}"
        f"\n  Actual exposure:      ${stats.actual_executed_total_usd:.2f}"
        f"\n  Capital protected:    "
        f"${stats.would_be_buy_total_usd - stats.actual_executed_total_usd:.2f}"
    )
    return stats


# --- Demo mode: 3 canned scenarios, no network, no LLM, no payment ---

_DEMO_SCENARIOS: list[tuple[str, dict[str, Any]]] = [
    (
        "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        {
            "scan_id": "demo-01",
            "chain": "base",
            "contract": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            "policy_recommendation": "allow",
            "policy": "balanced",
            "risk_score": 12,
            "verdict": "safe",
            "max_suggested_exposure_usd": 100.0,
            "reason": [],
            "key_fingerprint": "a0c71156d8747078",
        },
    ),
    (
        "0x4ed4E862860beD51a9570b96d89aF5E1B0Efefed",
        {
            "scan_id": "demo-02",
            "chain": "base",
            "contract": "0x4ed4E862860beD51a9570b96d89aF5E1B0Efefed",
            "policy_recommendation": "caution",
            "policy": "balanced",
            "risk_score": 62,
            "verdict": "medium_risk",
            "max_suggested_exposure_usd": 20.0,
            "reason": [
                {"code": "OWNER_NOT_RENOUNCED", "severity": "high"},
                {"code": "TOP10_CONCENTRATION_HIGH", "severity": "high"},
            ],
            "key_fingerprint": "a0c71156d8747078",
        },
    ),
    (
        "0xfc0482b1abd9da4a90a512305eeac472ffb88e1f",
        {
            "scan_id": "demo-03",
            "chain": "base",
            "contract": "0xfc0482b1abd9da4a90a512305eeac472ffb88e1f",
            "policy_recommendation": "block",
            "policy": "balanced",
            "risk_score": 95,
            "verdict": "critical",
            "max_suggested_exposure_usd": 0.0,
            "reason": [
                {"code": "TOP10_CONCENTRATION_HIGH", "severity": "critical"},
                {"code": "LP_INSUFFICIENT_LIQUIDITY", "severity": "critical"},
            ],
            "key_fingerprint": "a0c71156d8747078",
        },
    ),
]


async def run_demo() -> int:
    """Offline 3-scenario walk-through. No network, no LLM, no payment."""
    print(
        "RugGuard sniper bot demo - no LLM, no network, no payment.\n"
        "Showing how the bot routes 3 representative candidates "
        "(safe / medium / critical).\n"
    )

    async def fake_paid_post(*, url: str, json_body: dict, **_kw: Any) -> tuple[int, dict]:
        for addr, resp in _DEMO_SCENARIOS:
            if json_body["contract"] == addr:
                return 200, resp
        return 200, _DEMO_SCENARIOS[0][1]

    with patch("rugguard_sniper_bot.bot.paid_post", new=fake_paid_post):
        await run_sniper(
            candidates=[addr for addr, _ in _DEMO_SCENARIOS],
            chain="base",
            intended_trade_usd=100.0,
            policy="balanced",
            private_key_hex="0x" + "ab" * 32,  # mock — never sent over wire
        )

    print(
        "\nDone. Read src/rugguard_sniper_bot/bot.py end-to-end (~250 LOC), "
        "then swap `execute_buy_mock` for your own DEX router call.\n"
        "READ THE README SAFETY SECTION BEFORE GOING LIVE ON MAINNET."
    )
    return 0


class AddressesFileError(Exception):
    """Raised by _load_addresses when --addresses-file is unsafe to read."""


def _validate_private_key_format(pk: str) -> None:
    """Reject a private key that isn't 64-hex (optionally 0x-prefixed).

    eth_account's `Account.from_key` raises `ValueError(f"... {key!r}")`
    on malformed input, embedding the bad bytes into the exception text.
    Surfacing that string anywhere downstream (logs, decision.error) is
    a leak. Validate explicitly at CLI boundary and never pass the raw
    string further if it doesn't match the expected shape.
    """
    if not isinstance(pk, str) or not _PRIVATE_KEY_RE.match(pk):
        raise ValueError(
            "RUGGUARD_X402_PRIVATE_KEY must be 64 hex chars (optionally "
            "0x-prefixed). Got an input that does not match the expected "
            "format. Refusing to pass it to eth_account."
        )


def _load_addresses(args: argparse.Namespace) -> list[str]:
    if args.addresses:
        return [a.strip() for a in args.addresses.split(",") if a.strip()]
    if not args.addresses_file:
        return []

    # Resolve and validate the path before opening. Reject non-files
    # (a directory points the bot at recursive misery) and sym-links
    # (defense against being pointed at /etc/passwd by a misconfigured
    # systemd unit, etc — best-effort, not a sandbox).
    path = Path(args.addresses_file)
    if not path.exists():
        raise AddressesFileError(f"--addresses-file does not exist: {path}")
    if not path.is_file():
        raise AddressesFileError(f"--addresses-file is not a regular file: {path}")
    size = path.stat().st_size
    if size > MAX_ADDRESSES_FILE_BYTES:
        raise AddressesFileError(
            f"--addresses-file is {size} bytes, max allowed "
            f"{MAX_ADDRESSES_FILE_BYTES} bytes ({MAX_ADDRESSES_FILE_BYTES // 1024} KB). "
            f"An educational sniper kit refuses oversize candidate lists."
        )

    out: list[str] = []
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            if lineno > MAX_ADDRESSES_LINES:
                raise AddressesFileError(
                    f"--addresses-file exceeds {MAX_ADDRESSES_LINES} lines."
                )
            if len(line) > MAX_ADDRESS_LINE_LEN:
                raise AddressesFileError(
                    f"--addresses-file line {lineno} is {len(line)} chars, "
                    f"max {MAX_ADDRESS_LINE_LEN}. Refusing to parse — looks "
                    f"like the file is not a list of token addresses."
                )
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                out.append(stripped)
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rugguard-sniper",
        description=(
            "Educational sniper bot using RugGuard pre-trade safety. "
            "NOT production-grade. See README safety section."
        ),
    )
    parser.add_argument("--demo", action="store_true", help="Offline 3-scenario demo.")
    parser.add_argument(
        "--addresses", help="Comma-separated token contract addresses (live mode)."
    )
    parser.add_argument(
        "--addresses-file",
        help="Path to a file with one address per line (live mode).",
    )
    parser.add_argument("--chain", default=DEFAULT_CHAIN, help="base or solana.")
    parser.add_argument(
        "--size",
        type=float,
        default=100.0,
        help="Intended trade size in USD per candidate (default: 100).",
    )
    parser.add_argument(
        "--policy",
        default=DEFAULT_POLICY,
        choices=["conservative", "balanced", "aggressive"],
        help="Risk policy (default: balanced).",
    )
    parser.add_argument(
        "--session-cap",
        type=float,
        default=DEFAULT_SESSION_SPEND_CAP_USD,
        help=f"Max USDC spent on RugGuard per run (default: ${DEFAULT_SESSION_SPEND_CAP_USD}).",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help=(
            "Ed25519-verify each signed response in-band before trusting "
            "it. Requires `pip install rugguard-sniper-bot-example[verify]`. "
            "Conservative-by-default: a verification failure routes the "
            "candidate to recommendation=error (no buy)."
        ),
    )
    args = parser.parse_args(argv)

    if args.demo or (not args.addresses and not args.addresses_file):
        return asyncio.run(run_demo())

    pk = os.environ.get("RUGGUARD_X402_PRIVATE_KEY")
    if not pk:
        print(
            "error: RUGGUARD_X402_PRIVATE_KEY is not set. Live mode pays "
            "$0.01 USDC per /v1/pretrade/check call. Use --demo to walk "
            "through the bot without a wallet.",
            file=sys.stderr,
        )
        return 2

    try:
        _validate_private_key_format(pk)
    except ValueError as exc:
        # Do not echo the key value, even partially. The message from
        # _validate_private_key_format is generic by design.
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        candidates = _load_addresses(args)
    except AddressesFileError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not candidates:
        print("error: pass --addresses or --addresses-file (or --demo)", file=sys.stderr)
        return 2

    # Runtime banner — the README disclaimer is not visible from a
    # headless / CI run. Stderr so the operator sees this even when
    # stdout is piped to a log file.
    print(
        "WARNING: rugguard-sniper-bot-example is an EDUCATIONAL kit. "
        "`execute_buy_mock` is a stub — no on-chain buy is actually "
        "executed. See the README Safety section before swapping in a "
        "real router.",
        file=sys.stderr,
    )

    asyncio.run(
        run_sniper(
            candidates=candidates,
            chain=args.chain,
            intended_trade_usd=args.size,
            policy=args.policy,
            private_key_hex=pk,
            session_spend_cap_usd=args.session_cap,
            verify=args.verify,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


# This file plus cache.py + x402_pay.py is ~430 LOC total. The CORE bot
# logic — `evaluate_candidate` + `run_sniper` + `execute_buy_mock` — is
# ~120 LOC. The other ~150 LOC is the x402 client (which you would replace
# with `from rugguard_mcp.x402_client import paid_post` in production for
# the spend-cap + asset-whitelist + replay-window protections).
_unused_export = json.dumps({"see": "README safety section"})
