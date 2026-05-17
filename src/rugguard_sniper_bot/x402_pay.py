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

import httpx
from eth_account import Account
from eth_account.messages import encode_typed_data


class X402PaymentError(RuntimeError):
    """Raised when the x402 round-trip fails (invalid 402, payment rejected, etc.)."""


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


def _validate_payment_requirements(req: dict[str, Any]) -> None:
    """Asset / network / EIP-712 domain whitelist.

    Run BEFORE the EIP-3009 signature so a malicious 402 cannot trick us
    into draining a non-USDC token the user happens to also hold.
    """
    network = req.get("network")
    expected_asset = _USDC_ADDRESSES.get(network or "")
    if expected_asset is None:
        raise X402PaymentError(
            f"refused: network {network!r} is not in the USDC whitelist "
            f"({list(_USDC_ADDRESSES)})"
        )
    if (req.get("asset") or "").lower() != expected_asset.lower():
        raise X402PaymentError(
            f"refused: server asked us to sign for asset {req.get('asset')!r}, "
            f"expected USDC at {expected_asset} on {network}"
        )
    extra = req.get("extra") or {}
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
) -> tuple[int, dict[str, Any]]:
    """POST `json_body` to `url`, paying via x402 if the server returns 402.

    Returns (status_code, response_body). On payment failure, raises
    X402PaymentError with the server-reported reason.

    The JSON body is sent on BOTH the initial probe AND the signed retry
    because FastAPI's payment dependency runs before request-body parsing.
    The 402 short-circuits before the body is consumed server-side.
    """
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

        _validate_payment_requirements(req)

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
