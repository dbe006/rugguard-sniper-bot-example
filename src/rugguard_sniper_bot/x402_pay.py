"""Minimal x402 v1 client for POST /v1/pretrade/check.

A pedagogical version (~150 LOC) of the same 402-then-pay-then-retry flow
the rugguard-mcp x402_client uses, scoped strictly to POST + JSON body
because that is what /v1/pretrade/check accepts. Read end-to-end as the
canonical reference for "how to pay an x402 POST".

Intentionally NOT spend-capped here. If you wire it into a long-running
agent, add a budget check at the caller layer. For production-grade caps
plus replay-window protection, install `rugguard-mcp` and import
`from rugguard_mcp.x402_client import paid_post` instead.

Asset whitelist IS enforced: refuses to sign for anything other than
canonical USDC on Base / Base Sepolia. A malicious 402 response trying
to drain a different EIP-3009 token in the wallet is rejected before
the EIP-3009 signature is computed.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from typing import Any
from urllib.parse import urlparse

import httpx
from eth_account import Account
from eth_account.messages import encode_typed_data


class X402PaymentError(RuntimeError):
    """Raised when the x402 round-trip fails (invalid 402, payment rejected, etc.)."""


# USDC microunits per USD. EIP-3009 amounts in the 402 are advertised in
# atomic units; we convert to USD before applying the caller-supplied
# per-call max so the limit is meaningful regardless of decimals drift.
_USDC_DECIMALS = 6

# Loopback hostnames that bypass the https requirement — useful for dev
# against a local RugGuard. Any other plaintext host is refused to defeat
# trade-intent leakage and MITM-driven tampering of policy_recommendation.
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})


def _validate_https_scheme(url: str) -> None:
    """Refuse non-https URLs except for loopback dev hosts.

    A plaintext api_url leaks the trade intent (chain, contract,
    intended_trade_usd, policy) in flight AND opens a MITM path that
    can tamper with the returned policy_recommendation. The companion
    rugguard-verify CLI enforces the same rule on its pubkey URL —
    keeping the kits consistent removes a class of footguns where a
    user assumes one and gets the other.
    """
    parsed = urlparse(url)
    if parsed.scheme.lower() == "https":
        return
    if parsed.scheme.lower() == "http" and (parsed.hostname or "").lower() in _LOOPBACK_HOSTS:
        return
    raise X402PaymentError(
        f"refused: api_url must use https:// (got {url!r}). "
        "Plaintext http is only allowed for loopback dev hosts "
        f"({sorted(_LOOPBACK_HOSTS)})."
    )


# USDC contract addresses (Coinbase official Base deployments).
_USDC_ADDRESSES = {
    "base": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "base-sepolia": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
}

# EIP-712 USDC v2 domain bindings — refuse anything else.
_EXPECTED_EIP712_NAME = "USD Coin"
_EXPECTED_EIP712_VERSION = "2"

# EIP-3009 signature validBefore window. Tight enough to defeat header replay
# even though Coinbase has a 60s ceiling in spec.
_SIG_VALID_WINDOW_SECONDS = 10

_BASE_CHAIN_ID = 8453


def _validate_payment_requirements(
    req: dict[str, Any], *, max_amount_usdc: float | None = None
) -> None:
    """Asset / network / EIP-712 domain / amount whitelist.

    Run BEFORE the EIP-3009 signature so a malicious 402 cannot trick us
    into draining a non-USDC token the user happens to also hold, OR
    price-gouge a single round-trip if the caller set a per-call ceiling.

    `max_amount_usdc` is the caller-asserted maximum the round-trip is
    willing to settle. If the 402's `maxAmountRequired` (in USDC atomic
    units) exceeds it, the call is refused before signing. Used by the
    sniper bot to defend against a 402 that suddenly advertises 10x the
    expected $0.01 price.
    """
    network = req.get("network")
    if not isinstance(network, str):
        # Defensive isinstance check (a malicious 402 with network=None or
        # network=<dict> would otherwise hit `.get(None)` and produce a
        # less-informative error). Mirrors what rugguard-mcp enforces.
        raise X402PaymentError(
            f"refused: 402 'network' must be a string, got {type(network).__name__}"
        )
    expected_asset = _USDC_ADDRESSES.get(network)
    if expected_asset is None:
        raise X402PaymentError(
            f"refused: network {network!r} is not in the USDC whitelist "
            f"({list(_USDC_ADDRESSES)})"
        )
    asset = req.get("asset")
    if not isinstance(asset, str) or asset.lower() != expected_asset.lower():
        raise X402PaymentError(
            f"refused: server asked us to sign for asset {asset!r}, "
            f"expected USDC at {expected_asset} on {network}"
        )
    extra = req.get("extra")
    if not isinstance(extra, dict):
        raise X402PaymentError(
            f"refused: 402 'extra' must be a dict, got {type(extra).__name__}"
        )
    if extra.get("name") != _EXPECTED_EIP712_NAME:
        raise X402PaymentError(
            f"refused: EIP-712 domain name {extra.get('name')!r} != "
            f"expected {_EXPECTED_EIP712_NAME!r}"
        )
    if extra.get("version") != _EXPECTED_EIP712_VERSION:
        raise X402PaymentError(
            f"refused: EIP-712 domain version {extra.get('version')!r} != "
            f"expected {_EXPECTED_EIP712_VERSION!r}"
        )
    if max_amount_usdc is not None:
        try:
            atomic = int(req.get("maxAmountRequired", 0))
        except (TypeError, ValueError) as exc:
            raise X402PaymentError(
                f"refused: 402 maxAmountRequired is not a parseable integer "
                f"({req.get('maxAmountRequired')!r})"
            ) from exc
        amount_usdc = atomic / (10**_USDC_DECIMALS)
        if amount_usdc > max_amount_usdc:
            raise X402PaymentError(
                f"refused: 402 advertised ${amount_usdc:.6f} USDC, caller "
                f"capped this call at ${max_amount_usdc:.6f}. A surprise price "
                "increase or a hostile 402 — refusing to sign."
            )


def _build_typed_data(
    *, payer: str, receiver: str, value: int, asset_addr: str
) -> dict[str, Any]:
    """Build the EIP-712 TransferWithAuthorization payload USDC will verify."""
    now = int(time.time())
    nonce = "0x" + secrets.token_hex(32)
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "TransferWithAuthorization": [
                {"name": "from", "type": "address"},
                {"name": "to", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "validAfter", "type": "uint256"},
                {"name": "validBefore", "type": "uint256"},
                {"name": "nonce", "type": "bytes32"},
            ],
        },
        "primaryType": "TransferWithAuthorization",
        "domain": {
            "name": _EXPECTED_EIP712_NAME,
            "version": _EXPECTED_EIP712_VERSION,
            "chainId": _BASE_CHAIN_ID,
            "verifyingContract": asset_addr,
        },
        "message": {
            "from": payer,
            "to": receiver,
            "value": value,
            "validAfter": now - 5,  # 5s clock-skew tolerance backwards
            "validBefore": now + _SIG_VALID_WINDOW_SECONDS,
            "nonce": nonce,
        },
    }


def _encode_payment_header(typed_data: dict[str, Any], signature: str, network: str) -> str:
    """Base64-encode the x402 v1 PaymentPayload."""
    payload = {
        "x402Version": 1,
        "scheme": "exact",
        "network": network,
        "payload": {
            "signature": signature,
            "authorization": {
                "from": typed_data["message"]["from"],
                "to": typed_data["message"]["to"],
                "value": str(typed_data["message"]["value"]),
                "validAfter": str(typed_data["message"]["validAfter"]),
                "validBefore": str(typed_data["message"]["validBefore"]),
                "nonce": typed_data["message"]["nonce"],
            },
        },
    }
    return base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")


async def paid_post(
    *,
    url: str,
    json_body: dict[str, Any],
    private_key_hex: str,
    timeout_seconds: float = 30.0,
    max_amount_usdc: float | None = None,
) -> tuple[int, dict[str, Any]]:
    """POST `json_body` to `url`, paying via x402 if the server returns 402.

    Returns (status_code, response_body). On payment failure, raises
    X402PaymentError with the server-reported reason.

    Args:
        url: must use https:// scheme (or http:// against a loopback host
            for dev). Plaintext to a non-loopback host is refused before
            the probe.
        json_body: sent on BOTH the initial probe AND the signed retry
            because FastAPI's payment dependency runs before request-body
            parsing — the 402 short-circuits before the body is consumed.
        private_key_hex: EOA holder of USDC on Base ; signs EIP-3009.
        timeout_seconds: per-request httpx timeout.
        max_amount_usdc: optional per-call USDC ceiling. If set, the 402's
            `maxAmountRequired` is converted to USD and compared ; a 402
            advertising more than this is refused before signing. Defends
            against (a) silent server-side price changes and (b) hostile
            402 responses that try to price-gouge a single round-trip.
    """
    _validate_https_scheme(url)
    account = Account.from_key(private_key_hex.removeprefix("0x"))

    async with httpx.AsyncClient(timeout=timeout_seconds) as client:
        first = await client.post(url, json=json_body)
        if first.status_code != 402:
            return first.status_code, first.json()

        body = first.json()
        try:
            req = body["accepts"][0]
        except (KeyError, IndexError, TypeError) as exc:
            raise X402PaymentError("invalid_402_body") from exc

        _validate_payment_requirements(req, max_amount_usdc=max_amount_usdc)

        typed = _build_typed_data(
            payer=account.address,
            receiver=req["payTo"],
            value=int(req["maxAmountRequired"]),
            asset_addr=req["asset"],
        )
        signable = encode_typed_data(full_message=typed)
        signed = Account.sign_message(signable, private_key=account.key)
        sig = signed.signature.hex()
        if not sig.startswith("0x"):
            sig = "0x" + sig
        header = _encode_payment_header(typed, sig, req["network"])

        second = await client.post(url, json=json_body, headers={"X-Payment": header})
        if second.status_code == 402:
            err = (second.json().get("error") if second.text else None) or "unknown"
            raise X402PaymentError(f"payment_rejected:{err}")
        return second.status_code, second.json()
