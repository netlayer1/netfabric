"""
lld_engine.py — LLD compliance check engine

Parses a YAML LLD template and checks each rule against a running config string.
Returns a list of CheckResult dicts.
"""

import re
import logging
import yaml
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

SUPPORTED_TYPES = {
    "must_contain",
    "must_not_contain",
    "must_match_pattern",
    "must_not_match_pattern",
    "block_must_contain",
    "block_must_not_contain",
}


def _parse_blocks(config: str) -> Dict[str, List[str]]:
    """Parse running config into {header: [children]} blocks."""
    blocks: Dict[str, List[str]] = {}
    current = None
    for line in config.splitlines():
        if not line.strip() or line.strip().startswith("!"):
            continue
        if not line[0].isspace():
            current = line.strip()
            if current not in blocks:
                blocks[current] = []
        else:
            if current:
                blocks[current].append(line.strip())
    return blocks


def _config_lines(config: str) -> List[str]:
    """Return all non-empty, non-comment lines stripped."""
    return [
        l.strip() for l in config.splitlines()
        if l.strip() and not l.strip().startswith("!")
    ]


def run_compliance(yaml_content: str, running_config: str) -> List[Dict[str, Any]]:
    """
    Parse yaml_content and check each rule against running_config.

    Returns list of dicts:
      { id, description, type, status: 'pass'|'fail', detail }
    """
    try:
        template = yaml.safe_load(yaml_content)
    except yaml.YAMLError as e:
        return [{"id": "yaml_parse_error", "description": "YAML parse error",
                 "type": "internal", "status": "fail", "detail": str(e)}]

    if not isinstance(template, dict):
        return [{"id": "yaml_structure_error", "description": "YAML must be a mapping with a 'checks' key",
                 "type": "internal", "status": "fail",
                 "detail": f"Got {type(template).__name__} instead of dict. Wrap your checks under 'checks:' at the top level."}]

    checks = template.get("checks", [])
    if not checks:
        return [{"id": "no_checks", "description": "No checks defined in template",
                 "type": "internal", "status": "fail", "detail": "Add at least one check."}]

    lines  = _config_lines(running_config)
    blocks = _parse_blocks(running_config)
    results = []

    for check in checks:
        cid   = str(check.get("id", "unknown"))
        cdesc = check.get("description", cid)
        ctype = check.get("type", "")

        if ctype not in SUPPORTED_TYPES:
            results.append({"id": cid, "description": cdesc, "type": ctype,
                             "status": "fail", "detail": f"Unknown check type: '{ctype}'"})
            continue

        try:
            result = _run_check(check, ctype, lines, blocks)
        except Exception as e:
            result = {"status": "fail", "detail": f"Check error: {e}"}

        results.append({
            "id": cid,
            "description": cdesc,
            "type": ctype,
            "status": result["status"],
            "detail": result.get("detail", ""),
        })

    return results


def _run_check(check: dict, ctype: str, lines: List[str], blocks: Dict[str, List[str]]) -> dict:

    # ── must_contain ─────────────────────────────────────────
    if ctype == "must_contain":
        value = check["value"].strip()
        found = any(l == value or l.startswith(value) for l in lines)
        return {
            "status": "pass" if found else "fail",
            "detail": "" if found else f"Missing: '{value}'",
        }

    # ── must_not_contain ─────────────────────────────────────
    if ctype == "must_not_contain":
        value = check["value"].strip()
        hits = [l for l in lines if l == value or l.startswith(value)]
        return {
            "status": "fail" if hits else "pass",
            "detail": f"Found forbidden line: '{hits[0]}'" if hits else "",
        }

    # ── must_match_pattern ───────────────────────────────────
    if ctype == "must_match_pattern":
        pattern = check["pattern"]
        hits = [l for l in lines if re.search(pattern, l)]
        return {
            "status": "pass" if hits else "fail",
            "detail": f"Matched: '{hits[0]}'" if hits else f"No line matched pattern: '{pattern}'",
        }

    # ── must_not_match_pattern ───────────────────────────────
    if ctype == "must_not_match_pattern":
        pattern = check["pattern"]
        hits = [l for l in lines if re.search(pattern, l)]
        return {
            "status": "fail" if hits else "pass",
            "detail": f"Forbidden pattern found: '{hits[0]}'" if hits else "",
        }

    # ── block_must_contain ───────────────────────────────────
    if ctype == "block_must_contain":
        block_prefix = check["block"].strip()
        value = check["value"].strip()
        matching_blocks = {h: children for h, children in blocks.items()
                           if h.startswith(block_prefix)}
        if not matching_blocks:
            return {"status": "fail", "detail": f"Block '{block_prefix}' not found in config"}
        missing_in = []
        for header, children in matching_blocks.items():
            if not any(c == value or c.startswith(value) for c in children):
                missing_in.append(header)
        if missing_in:
            return {"status": "fail",
                    "detail": f"'{value}' missing in: {', '.join(missing_in)}"}
        return {"status": "pass", "detail": ""}

    # ── block_must_not_contain ───────────────────────────────
    if ctype == "block_must_not_contain":
        block_prefix = check["block"].strip()
        value = check["value"].strip()
        matching_blocks = {h: children for h, children in blocks.items()
                           if h.startswith(block_prefix)}
        found_in = []
        for header, children in matching_blocks.items():
            if any(c == value or c.startswith(value) for c in children):
                found_in.append(header)
        if found_in:
            return {"status": "fail",
                    "detail": f"Forbidden '{value}' found in: {', '.join(found_in)}"}
        return {"status": "pass", "detail": ""}

    return {"status": "fail", "detail": "Unhandled check type"}
