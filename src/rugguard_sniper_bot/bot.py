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
import sys
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import patch

from rugguard_sniper_bot.cache import DecisionCache
from rugguard_sniper_bot.x402_pay import X402PaymentError, paid_post

DEFAULT_API_URL = "https://rugguard.redfleet.fr"
DEFAULT_CHAIN = "base"
DEFAULT_POLICY = "balanced"

# Hard session ceiling on RugGuard spend. Caps the worst case where the bot
# is mis-configured and burns the wallet through /v1/pretrade/check calls.
# Each call is $0.01 ; default cap of $1 covers 100 candidates per session,
# more than enough for an educational walk-through.
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
) -> SniperDecision:
    """Run /v1/pretrade/check on one candidate, map to a SniperDecision.

    Cache hits don't pay. Network / payment errors map to
    `recommendation="error"` and `executed_size_usd=0.0` —
    conservative-by-default."""
    if cache is not None:
        cached = cache.get(chain, contract)
        if cached is not None:
            return _decision_from_response(
                chain, contract, intended_trade_usd, cached
            )

    url = f"{api_url.rstrip('/')}/v1/pretrade/check"
    body = {
        "chain": chain,
        "contract": contract,
        "intended_trade_usd": intended_trade_usd,
        "policy": policy,
    }
    try:
        status, response = await paid_post(
            url=url, json_body=body, private_key_hex=private_key_hex
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
        return SniperDecision(
            chain=chain,
            contract=contract,
            intended_trade_usd=intended_trade_usd,
            recommendation="error",
            error=f"{type(exc).__name__}: {exc}",
        )

    if status != 200:
        return SniperDecision(
            chain=chain,
            contract=contract,
            intended_trade_usd=intended_trade_usd,
            recommendation="error",
            error=f"non_200 status={status}",
        )

    if cache is not None:
        cache.put(chain, contract, response)
    return _decision_from_response(chain, contract, intended_trade_usd, response)


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
    caution / blocked-out for block."""
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
) -> SniperStats:
    """Main bot loop. Pre-trade-checks each candidate, mock-executes
    according to RugGuard's recommendation, aggregates stats. Aborts
    early if `session_spend_cap_usd` would be breached."""
    cache = DecisionCache(ttl_seconds=300)
    stats = SniperStats()
    print(
        f"Sniper bot: {len(candidates)} candidates on {chain}, "
        f"policy={policy}, intended_size=${intended_trade_usd}, "
        f"session cap=${session_spend_cap_usd}\n"
    )

    for contract in candidates:
        # Each /v1/pretrade/check costs $0.01 (USDC on Base). Stop the loop
        # if the next call would breach the session cap. Defensive against
        # a mistakenly-massive candidate list.
        if stats.rugguard_spend_usdc + 0.01 > session_spend_cap_usd:
            print(
                f"\nSession spend cap reached "
                f"(${stats.rugguard_spend_usdc:.2f}/${session_spend_cap_usd}). "
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
        )
        stats.candidates_evaluated += 1
        stats.rugguard_spend_usdc += 0.01  # bookkeeping only ; real settle is on-chain
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


def _load_addresses(args: argparse.Namespace) -> list[str]:
    if args.addresses:
        return [a.strip() for a in args.addresses.split(",") if a.strip()]
    if args.addresses_file:
        with open(args.addresses_file, encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    return []


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

    candidates = _load_addresses(args)
    if not candidates:
        print("error: pass --addresses or --addresses-file (or --demo)", file=sys.stderr)
        return 2

    asyncio.run(
        run_sniper(
            candidates=candidates,
            chain=args.chain,
            intended_trade_usd=args.size,
            policy=args.policy,
            private_key_hex=pk,
            session_spend_cap_usd=args.session_cap,
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
