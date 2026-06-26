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
    # 10-node license for Acme Corp (unbound)
    python scripts/generate_license.py acme-corp 10

    # 10-node license bound to a specific machine
    python scripts/generate_license.py acme-corp 10 --machine-id 550e8400-e29b-41d4-a716-446655440000

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


def generate_license(customer_id: str, tier: str, machine_id: str = None) -> dict:
    if tier not in TIERS:
        raise ValueError(
            f"Unknown tier '{tier}'. Valid tiers: {', '.join(TIERS)}"
        )

    now = datetime.now(timezone.utc)
    payload = {
        "customer_id": customer_id,
        "tier": tier,
        "max_nodes": TIERS[tier],
        "issued_at": now.isoformat(),
        "expires_at": now.replace(year=now.year + 1).isoformat(),
    }

    if machine_id:
        payload["machine_id"] = machine_id

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
    parser.add_argument(
        "--machine-id",
        default=None,
        help="Bind license to a specific machine ID (customer copies from the UI)",
    )
    args = parser.parse_args()

    try:
        license_data = generate_license(args.customer_id, args.tier, args.machine_id)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    out_path = Path(args.out) if args.out else Path.home() / "Desktop" / f"license_{args.customer_id}.json"
    out_path.write_text(json.dumps(license_data, indent=2))

    max_nodes = TIERS[args.tier]
    cap_str = "unlimited" if max_nodes == -1 else str(max_nodes)
    print(f"✓ License written to: {out_path}")
    print(f"  customer_id : {args.customer_id}")
    print(f"  tier        : {args.tier}")
    print(f"  max_nodes   : {cap_str}")
    print(f"  issued_at   : {license_data['issued_at']}")
    print(f"  expires_at  : {license_data['expires_at']}")
    if args.machine_id:
        print(f"  machine_id  : {args.machine_id}  ← bound to this machine only")
    print()
    print("Send the license file to the customer.")
    print("They upload it via the web UI on first login.")


if __name__ == "__main__":
    main()
