"""Educational Base sniper bot integrating RugGuard's pre-trade safety check.

This package is **NOT production-grade**. It demonstrates the canonical
sniper integration pattern:

  1. Have a list of candidate token addresses (from any source — on-chain
     mempool listener, indexer webhook, /v1/discover poll, etc.).
  2. For each candidate, call RugGuard's /v1/pretrade/check to get a
     prescriptive block | caution | allow + a clamped exposure cap.
  3. Skip the block-ed tokens, downsize the caution-ed ones, buy at full
     size for allow.

What this package does NOT do (and what you must add for production):
  - actual on-chain execution (Uniswap / Aerodrome router calls)
  - mempool / pending-tx subscription
  - position management, stop loss, take profit
  - retry policy, circuit breakers, rate limiting
  - structured logging + alerting
  - hardware wallet integration

Read the source end-to-end (~170 LOC of bot logic, ~150 LOC of
copy-pasted x402 client) before forking. Treat the wallet as a budget
ceiling — fund it only with what you can afford to lose.
"""

from rugguard_sniper_bot.bot import (
    SniperDecision,
    SniperStats,
    evaluate_candidate,
    run_sniper,
)
from rugguard_sniper_bot.cache import DecisionCache
from rugguard_sniper_bot.x402_pay import X402PaymentError, paid_post

__all__ = [
    "DecisionCache",
    "SniperDecision",
    "SniperStats",
    "X402PaymentError",
    "evaluate_candidate",
    "paid_post",
    "run_sniper",
]

__version__ = "0.1.3"
