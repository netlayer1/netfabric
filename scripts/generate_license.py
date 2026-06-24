"""
generate_license.py — NetFabric offline license generator
---------------------------------------------------------
Run this tool on YOUR machine only. Never ship this file to customers.

Usage:
    python scripts/generate_license.py <customer_id> <tier> [--out PATH]

Tiers:
    1           →  1 device  (evaluation / POC)
    10          →  10 devices
    100         →  100 devices
    1000        →  1000 devices
    unlimited   →  no cap

Examples:
    # 10-node license for Acme Corp
    python scripts/generate_license.py acme-corp 10

    # 100-node license, custom output path
    python scripts/generate_license.py bigco-inc 100 --out /tmp/bigco.json

    # Unlimited license for internal use
    python scripts/generate_license.py internal unlimited
"""

import json
import hmac
import hashlib
import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

# ── Must match the key baked into license_guard.py ───────────────────────────
_SECRET_KEY = b"nf-license-secret-change-before-release"

TIERS: dict[str, int] = {
    "1": 1,
    "10": 10,
    "100": 100,
    "1000": 1000,
    "unlimited": -1,   # -1 = no cap inside the runtime guard
}


def generate_license(customer_id: str, tier: str) -> dict:
    if tier not in TIERS:
        raise ValueError(
            f"Unknown tier '{tier}'. Valid tiers: {', '.join(TIERS)}"
        )

    payload = {
        "customer_id": customer_id,
        "tier": tier,
        "max_nodes": TIERS[tier],
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }

    # Sign the canonical JSON (sort_keys so order never matters)
    body = json.dumps(payload, sort_keys=True).encode()
    payload["signature"] = hmac.new(_SECRET_KEY, body, hashlib.sha256).hexdigest()

    return payload


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a signed NetFabric license file."
    )
    parser.add_argument("customer_id", help="Customer identifier (e.g. acme-corp)")
    parser.add_argument(
        "tier",
        choices=list(TIERS.keys()),
        help="License tier: 1 | 10 | 100 | 1000 | unlimited",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Output path (default: license_<customer_id>.json in current dir)",
    )
    args = parser.parse_args()

    try:
        license_data = generate_license(args.customer_id, args.tier)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    out_path = Path(args.out) if args.out else Path(f"license_{args.customer_id}.json")
    out_path.write_text(json.dumps(license_data, indent=2))

    max_nodes = TIERS[args.tier]
    cap_str = "unlimited" if max_nodes == -1 else str(max_nodes)
    print(f"✓ License written to: {out_path}")
    print(f"  customer_id : {args.customer_id}")
    print(f"  tier        : {args.tier}")
    print(f"  max_nodes   : {cap_str}")
    print(f"  issued_at   : {license_data['issued_at']}")
    print()
    print("Send the license file to the customer.")
    print("They mount it at /app/license/license.json in their Docker setup.")


if __name__ == "__main__":
    main()
