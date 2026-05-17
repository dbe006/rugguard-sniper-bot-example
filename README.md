# rugguard-sniper-bot-example

> **⚠ Educational, not production-grade.** Read [Safety](#safety) before going live on mainnet.

An example Base sniper bot that demonstrates the canonical pre-trade safety integration with [RugGuard](https://rugguard.redfleet.fr). For each candidate token, the bot calls `/v1/pretrade/check`, then routes to a mock buy (sized by RugGuard's `max_suggested_exposure_usd`) or a skip log line based on `policy_recommendation`.

The bot **does not** actually execute on-chain. It logs what it would buy. Swap `execute_buy_mock` for your own DEX router call to make it real.

## Why

Sniper bots that buy fresh token launches are textbook rug-pull bait. A pre-trade safety gate cuts a measurable chunk of losses before they happen. This kit shows the smallest-viable integration: ~120 LOC of bot logic on top of RugGuard's `/v1/pretrade/check` endpoint.

## Install + offline demo

```bash
pip install rugguard-sniper-bot-example
rugguard-sniper --demo
```

The demo runs the bot through 3 representative candidates (safe USDC, fresh memecoin, drained pool) without paying or touching the network.

Expected output:

```
Sniper bot: 3 candidates on base, policy=balanced, intended_size=$100.0, session cap=$1.0

  [BUY  ] base:0x83358... score= 12 verdict=safe         size=$ 100.00/$100 reasons=[-] sig=a0c71156
  [BUY*] base:0x4ed4E... score= 62 verdict=medium_risk  size=$  20.00/$100 reasons=[OWNER_NOT_RENOUNCED, TOP10_CONCENTRATION_HIGH] sig=a0c71156
  [SKIP ] base:0xfc048... score= 95 verdict=critical    size=$   0.00/$100 reasons=[TOP10_CONCENTRATION_HIGH, LP_INSUFFICIENT_LIQUIDITY] sig=a0c71156

Session summary:
  candidates evaluated: 3
  executed (mock):      2
  skipped:              1
  RugGuard spend:       $0.03 USDC
  Would-be buy total:   $300.00
  Actual exposure:      $120.00
  Capital protected:    $180.00
```

The `[BUY*]` asterisk means "RugGuard clamped this from $100 to $20 due to medium risk". The `Capital protected` line shows the difference between naive-buy size and RugGuard-clamped size.

## Run with real candidates (live x402 payment)

```bash
# 1. Get a funded x402 wallet (Base mainnet, ≥ $0.05 USDC)
export RUGGUARD_X402_PRIVATE_KEY=0xYOUR_PRIVATE_KEY_HEX

# 2. Inline list
rugguard-sniper --addresses 0xABC...,0xDEF... --chain base --size 100 --policy balanced

# 3. Or from a file (one address per line, '#' comments OK)
rugguard-sniper --addresses-file tokens.txt --chain base --size 100
```

Each candidate costs $0.01 USDC. The bot enforces a hard `--session-cap` (default $1) and aborts before exceeding it.

## CLI flags

| Flag | Default | Description |
|---|---|---|
| `--demo` | `False` | Offline 3-scenario walk-through. No payment. |
| `--addresses` | — | Comma-separated token addresses to evaluate. |
| `--addresses-file` | — | File path, one address per line, `#` comments OK. |
| `--chain` | `base` | `base` or `solana`. |
| `--size` | `100.0` | Intended trade size in USD per candidate. |
| `--policy` | `balanced` | `conservative` / `balanced` / `aggressive`. |
| `--session-cap` | `1.0` | Hard USD cap on total RugGuard spend per run. |

## Policy modes (recap)

| Policy | Blocks at | Cautions at | Allows below |
|---|---|---|---|
| `conservative` | score ≥ 51 (medium_risk) | 26-50 | ≤ 25 |
| `balanced` *(default)* | score ≥ 71 (high_risk) | 51-70 | ≤ 50 |
| `aggressive` | score ≥ 91 (critical) | 71-90 | ≤ 70 |

`uncertain` verdict → `caution` in all modes.

## Library API

`bot.py` exports a few primitives you can call directly without using the CLI:

```python
from rugguard_sniper_bot import (
    evaluate_candidate, run_sniper, SniperDecision, SniperStats, DecisionCache,
)

decision = await evaluate_candidate(
    chain="base",
    contract="0xABC...",
    intended_trade_usd=100.0,
    policy="balanced",
    private_key_hex=YOUR_KEY,
    api_url="https://rugguard.redfleet.fr",
    cache=DecisionCache(),
)
# decision.recommendation in {"allow", "caution", "block", "error"}
# decision.executed_size_usd  ← clamped by RugGuard
```

## Safety

This is the most important section. **Read before going live on mainnet.**

### What this kit does NOT do (and what you must add)

- **No actual on-chain execution.** `execute_buy_mock` is a log line. Swap it for your Uniswap V2 / Aerodrome router integration before going live.
- **No mempool subscription.** A real sniper listens for `PoolCreated` / `PairCreated` events. Add a websockets-based listener (Alchemy / QuickNode / Helius).
- **No position management.** No stop-loss, take-profit, time-based exit. Build a separate `position_manager` module.
- **No retry / circuit breaker.** Network errors route to `recommendation="error"` and skip. Production should retry transient failures with backoff, alert on sustained failures.
- **No alerts / structured logging.** `print` is the only output. Wire `structlog` + a Telegram/Discord webhook before production.

### Recommended hardening

- **Use [`rugguard-mcp`](https://pypi.org/project/rugguard-mcp/) for production x402.** The bundled `x402_pay.py` here is pedagogical — it has an asset whitelist but **no spend caps**. The full `rugguard-mcp` ships session caps, 24h caps, file-locked TOCTOU-safe charge reservation, and replay-window protection.
- **Dedicated wallet.** Generate a fresh EOA, fund only with the USDC you can afford to lose. Treat the wallet balance itself as a hard cap.
- **Verify signed reports.** Production: install [`rugguard-verify`](https://pypi.org/project/rugguard-verify/) and validate every `SniperDecision`'s `signature_fingerprint` against `/v1/pubkey` before trusting it. The fingerprint is already surfaced in `SniperDecision.signature_fingerprint`.
- **Independent sanity check.** Don't trust RugGuard alone. Cross-check with at least one other signal (your own liquidity threshold, a different rug-scanner) for the trades that actually move money.

### Wallet hygiene

```bash
# DO NOT commit the private key
echo "RUGGUARD_X402_PRIVATE_KEY=0x..." >> .env
echo ".env" >> .gitignore
```

The bot reads the key from the env var only. Never accept it as a CLI flag (would leak into shell history + `ps` output).

## Companion packages

- [`rugguard-mcp`](https://pypi.org/project/rugguard-mcp/) — MCP server for Claude Desktop / Cursor / LangGraph
- [`rugguard-pydantic-ai-agent`](https://pypi.org/project/rugguard-pydantic-ai-agent/) — Pydantic AI typed tool
- [`rugguard-langgraph-agent`](https://pypi.org/project/rugguard-langgraph-agent/) — LangGraph node
- [`rugguard-verify`](https://pypi.org/project/rugguard-verify/) — Ed25519 signed-report verifier CLI

## License

MIT. See [LICENSE](LICENSE). Use at your own risk — this is example code, not investment advice.
