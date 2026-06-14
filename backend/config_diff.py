"""
config_diff.py — Parse Cisco IOS running-config into blocks and compute
the minimal delta (add + no-commands) to transform old config → new config.

IOS config structure:
  Top-level statement  (no leading whitespace)
    child line         (1+ leading spaces)
    child line
  Top-level statement
    ...

Algorithm:
  1. Parse both configs into OrderedDict of { header: [children] }
  2. Removed blocks  → emit  "no <header>"
  3. Added blocks    → emit  "<header>" + children
  4. Changed blocks  → enter context, emit "no <child>" for removals,
                       new child lines for additions
  5. Return ordered list of commands ready for send_config_set
"""

import re
from collections import OrderedDict
from typing import List, Dict, Tuple


# Lines to ignore entirely (comments, auto-generated timestamps, etc.)
_IGNORE = re.compile(
    r"^(!\s*|building configuration|current configuration|"
    r"ntp clock-period|last configuration change|"
    r"nvram config last updated)",
    re.IGNORECASE,
)

# Cisco IOS interface name abbreviation → canonical expansion
_IFACE_EXPAND = [
    (re.compile(r"^interface\s+lo(\d+)$",       re.IGNORECASE), r"interface Loopback\1"),
    (re.compile(r"^interface\s+gi(\S+)$",        re.IGNORECASE), r"interface GigabitEthernet\1"),
    (re.compile(r"^interface\s+fa(\S+)$",        re.IGNORECASE), r"interface FastEthernet\1"),
    (re.compile(r"^interface\s+te(\S+)$",        re.IGNORECASE), r"interface TenGigabitEthernet\1"),
    (re.compile(r"^interface\s+hu(\S+)$",        re.IGNORECASE), r"interface HundredGigE\1"),
    (re.compile(r"^interface\s+se(\S+)$",        re.IGNORECASE), r"interface Serial\1"),
    (re.compile(r"^interface\s+tu(\d+)$",        re.IGNORECASE), r"interface Tunnel\1"),
    (re.compile(r"^interface\s+vl(\d+)$",        re.IGNORECASE), r"interface Vlan\1"),
    (re.compile(r"^interface\s+po(\d+)$",        re.IGNORECASE), r"interface Port-channel\1"),
    (re.compile(r"^interface\s+mg(\S+)$",        re.IGNORECASE), r"interface MgmtEth\1"),
]


def _is_ignorable(line: str) -> bool:
    return bool(_IGNORE.search(line.strip()))


_INT_ABBREV = re.compile(r"^int(?:erface)?\s+", re.IGNORECASE)


def _normalize_iface(line: str) -> str:
    """Expand abbreviated interface names to their canonical IOS form."""
    indent = len(line) - len(line.lstrip())
    stripped = line.strip()

    # Normalize 'int ...' → 'interface ...' before applying expansion rules
    stripped = _INT_ABBREV.sub("interface ", stripped)

    for pattern, replacement in _IFACE_EXPAND:
        expanded = pattern.sub(replacement, stripped)
        if expanded != stripped:
            return " " * indent + expanded

    return " " * indent + stripped


def parse_blocks(config_text: str) -> "OrderedDict[str, List[str]]":
    """
    Parse a running-config into an ordered dict:
      { "interface GigabitEthernet0/0": [" description WAN", " ip address ..."], ... }

    Top-level lines with no children map to an empty list.
    """
    blocks: OrderedDict[str, List[str]] = OrderedDict()
    current_header: str | None = None

    for raw in config_text.splitlines():
        if _is_ignorable(raw) or not raw.strip():
            continue

        line = _normalize_iface(raw)

        if line[0] != " " and line[0] != "\t":
            # Top-level line
            current_header = line.rstrip()
            if current_header not in blocks:
                blocks[current_header] = []
        else:
            # Child line — belongs to the last top-level header
            if current_header is not None:
                blocks[current_header].append(line.rstrip())

    return blocks


def resolve_config(config_text: str, device_interfaces: List[str]) -> str:
    """
    Replace abbreviated interface names in config_text with canonical names
    sourced directly from the device's interface list.

    Strategy:
    1. Normalize the submitted name (expand 'int lo1' → 'Loopback1')
    2. Try to match against known device interfaces by type prefix + number
    3. If no match found (new interface), use the normalized canonical name
       so the device receives a valid command

    Example:
      device_interfaces = ["GigabitEthernet1", "Loopback0"]
      'int lo1'  → no match → 'interface Loopback1'   (new, canonical)
      'int lo0'  → matches 'Loopback0' → 'interface Loopback0'
      'int gi1'  → matches 'GigabitEthernet1' → 'interface GigabitEthernet1'
    """
    # Build a lookup: (type_prefix_lower, number) → canonical_name
    # e.g. ("loopback", "0") → "Loopback0"
    _iface_split = re.compile(r"^([A-Za-z\-]+)(\d[\d/.]*)$")
    device_map: Dict[tuple, str] = {}
    for iface in device_interfaces:
        m = _iface_split.match(iface)
        if m:
            device_map[(m.group(1).lower(), m.group(2))] = iface

    # Map short prefixes to canonical type prefixes used by the device
    _prefix_map = {
        "loopback": "Loopback",
        "lo":       "Loopback",
        "gigabitethernet": "GigabitEthernet",
        "gi":       "GigabitEthernet",
        "fastethernet": "FastEthernet",
        "fa":       "FastEthernet",
        "tengigabitethernet": "TenGigabitEthernet",
        "te":       "TenGigabitEthernet",
        "hundredgige": "HundredGigE",
        "hu":       "HundredGigE",
        "serial":   "Serial",
        "se":       "Serial",
        "tunnel":   "Tunnel",
        "tu":       "Tunnel",
        "vlan":     "Vlan",
        "vl":       "Vlan",
        "port-channel": "Port-channel",
        "po":       "Port-channel",
    }

    resolved_lines = []
    _int_line = re.compile(r"^(int(?:erface)?\s+)(\S+)$", re.IGNORECASE)

    for line in config_text.splitlines():
        stripped = line.strip()
        m = _int_line.match(stripped)
        if m:
            iface_arg = m.group(2)  # e.g. "lo1", "GigabitEthernet1"
            # Split into type + number
            im = _iface_split.match(iface_arg)
            if im:
                type_part = im.group(1).lower()
                num_part  = im.group(2)
                # Try exact device match first
                canonical = device_map.get((type_part, num_part))
                if canonical:
                    # Use the name exactly as the device reports it
                    indent = len(line) - len(line.lstrip())
                    resolved_lines.append(" " * indent + f"interface {canonical}")
                    continue
                # No match — new interface; build canonical name
                canonical_type = _prefix_map.get(type_part, iface_arg)
                if canonical_type != iface_arg:
                    indent = len(line) - len(line.lstrip())
                    resolved_lines.append(" " * indent + f"interface {canonical_type}{num_part}")
                    continue
        resolved_lines.append(line)

    return "\n".join(resolved_lines)


def generate_delta(old_config: str, new_config: str) -> List[str]:
    """
    Return the ordered list of IOS CLI commands that transform
    old_config into new_config.

    Includes:
      - "no <header>"               for removed top-level blocks
      - "<header>" + children       for new top-level blocks
      - "<header>" context entry    for changed blocks, followed by
          "no <child>" removals and new child additions
    """
    old = parse_blocks(old_config)
    new = parse_blocks(new_config)

    commands: List[str] = []

    old_keys = list(old.keys())
    new_keys = list(new.keys())
    old_set  = set(old_keys)
    new_set  = set(new_keys)

    # ── 1. Removed top-level blocks ──────────────────────────────────────
    for header in old_keys:
        if header not in new_set:
            commands.append(f"no {header.strip()}")

    # ── 2. Added top-level blocks ─────────────────────────────────────────
    for header in new_keys:
        if header not in old_set:
            commands.append(header)
            commands.extend(new[header])

    # ── 3. Changed blocks ─────────────────────────────────────────────────
    for header in new_keys:
        if header not in old_set:
            continue  # already handled above

        old_children = old[header]
        new_children = new[header]

        old_child_set = set(c.strip() for c in old_children)
        new_child_set = set(c.strip() for c in new_children)

        removed = old_child_set - new_child_set
        added   = new_child_set - old_child_set

        if not removed and not added:
            continue  # block unchanged

        commands.append(header)           # enter context

        for child in old_children:        # preserve removal order
            if child.strip() in removed:
                commands.append(f" no {child.strip()}")

        for child in new_children:        # preserve addition order
            if child.strip() in added:
                commands.append(child)

    return commands


def summarise_delta(commands: List[str]) -> Dict[str, int]:
    """Return { 'added': N, 'removed': N, 'total': N } from a delta list."""
    removed = sum(1 for c in commands if c.strip().startswith("no "))
    added   = len(commands) - removed
    return {"added": added, "removed": removed, "total": len(commands)}
