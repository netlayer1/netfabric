"""
license_guard.py — NetFabric license enforcement
Compiled with Nuitka as an extension module (.so).

The secret key is baked into this compiled binary.
The license file (license.json) is supplied by the customer and mounted at runtime.

Tiers:
    1       →  1 device
    10      →  10 devices
    100     →  100 devices
    1000    →  1000 devices
    unlimited → no cap (-1)
"""

import json
import hmac
import hashlib
import os

# ── Secret key baked into the compiled binary ─────────────────────────────────
# Change this before distributing. Keep it out of version control.
_SECRET_KEY = b"nf-license-secret-change-before-release"

# ── License file path — stored in the persistent data volume ─────────────────
# Override with NETFABRIC_LICENSE env var if needed.
_LICENSE_PATH = os.environ.get(
    "NETFABRIC_LICENSE", "/app/data/license.json"
)


def save_license(raw: dict) -> None:
    """
    Validate and persist a license dict to the data volume.
    Raises LicenseError if the signature is invalid.
    """
    import json as _json
    # Write to a temp copy of data dict (without signature) to verify
    check = dict(raw)
    provided_sig = check.pop("signature", None)
    if not provided_sig:
        raise LicenseError("License has no signature field.")
    body = _json.dumps(check, sort_keys=True).encode()
    expected = hmac.new(_SECRET_KEY, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(provided_sig, expected):
        raise LicenseError("License signature invalid — file may be tampered with.")
    os.makedirs(os.path.dirname(_LICENSE_PATH), exist_ok=True)
    with open(_LICENSE_PATH, "w") as fh:
        _json.dump(raw, fh, indent=2)

_VALID_TIERS = {"1": 1, "10": 10, "100": 100, "1000": 1000, "unlimited": -1}


class LicenseError(Exception):
    """Raised when the license is missing, invalid, or the node limit is hit."""


def _load_and_verify() -> dict:
    """
    Read, parse, and HMAC-verify the license file.
    Returns the payload dict (without the signature key) on success.
    Raises LicenseError on any failure.
    """
    try:
        with open(_LICENSE_PATH) as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise LicenseError(
            f"License file not found at {_LICENSE_PATH}. "
            "Mount your license.json and restart."
        )
    except json.JSONDecodeError:
        raise LicenseError("License file is not valid JSON.")

    # Pop signature before re-serialising the payload
    provided_sig = data.pop("signature", None)
    if not provided_sig:
        raise LicenseError("License file has no signature field.")

    # Reproduce the canonical serialisation used during generation
    body = json.dumps(data, sort_keys=True).encode()
    expected_sig = hmac.new(_SECRET_KEY, body, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(provided_sig, expected_sig):
        raise LicenseError(
            "License signature mismatch — the file may have been tampered with."
        )

    # Restore signature so callers can inspect if needed
    data["signature"] = provided_sig
    return data


def get_license_info() -> dict:
    """
    Return a sanitised summary of the active license.

    Returns:
        {
            "customer_id": str,
            "tier": str,          # "1" | "10" | "100" | "1000" | "unlimited"
            "max_nodes": int,     # -1 means unlimited
            "issued_at": str,
        }
    """
    lic = _load_and_verify()
    return {
        "customer_id": lic.get("customer_id", "unknown"),
        "tier": lic.get("tier", "unknown"),
        "max_nodes": lic.get("max_nodes", 0),
        "issued_at": lic.get("issued_at", "unknown"),
    }


def get_max_nodes() -> int:
    """Return the node cap from the license. -1 means unlimited."""
    lic = _load_and_verify()
    max_nodes = lic.get("max_nodes")
    if max_nodes is None:
        raise LicenseError("License file is missing 'max_nodes' field.")
    return int(max_nodes)


def enforce_node_limit(current_count: int) -> None:
    """
    Call this before adding a new device.

    Args:
        current_count: number of devices already in the database for this user.

    Raises:
        LicenseError: if adding one more device would exceed the licensed cap.
    """
    max_nodes = get_max_nodes()
    if max_nodes == -1:
        return  # unlimited tier — no cap

    if current_count >= max_nodes:
        raise LicenseError(
            f"Device limit reached ({max_nodes} device{'s' if max_nodes != 1 else ''} "
            f"on your current license tier). "
            f"Contact support to upgrade."
        )
