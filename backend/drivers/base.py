"""
base.py — Abstract base class for all network device drivers (NEDs).

Inspired by Cisco NSO's NED (Network Element Driver) architecture.
Each driver is a NED — it owns the protocol conversation with one vendor/platform.

NED concepts implemented here:
  - NED_ID        unique identity e.g. "cisco-ios-cli-6.115"
  - NED_VERSION   semver-style version string
  - PROTOCOL      transport: "cli" | "netconf" | "restconf"
  - CAPABILITIES  feature flags the NED supports
  - live_status_commands()  operational (non-config) data — separate from config
  - rollback_command()      native device rollback if supported

To add a new vendor NED:
  1. Create backend/drivers/<vendor>.py
  2. Subclass BaseDriver, set NED_ID / NED_VERSION / PROTOCOL / CAPABILITIES
  3. Implement all abstract methods
  4. Register it in backend/drivers/__init__.py
"""

import logging
import re
from abc import ABC, abstractmethod
from typing import Optional

_log = logging.getLogger(__name__)

# ── Shared YANG type-inference helpers (used by all NED cli_to_template impls) ─

_VALID_MASKS = {
    '0.0.0.0','128.0.0.0','192.0.0.0','224.0.0.0','240.0.0.0',
    '248.0.0.0','252.0.0.0','254.0.0.0','255.0.0.0',
    '255.128.0.0','255.192.0.0','255.224.0.0','255.240.0.0',
    '255.248.0.0','255.252.0.0','255.254.0.0','255.255.0.0',
    '255.255.128.0','255.255.192.0','255.255.224.0','255.255.240.0',
    '255.255.248.0','255.255.252.0','255.255.254.0','255.255.255.0',
    '255.255.255.128','255.255.255.192','255.255.255.224','255.255.255.240',
    '255.255.255.248','255.255.255.252','255.255.255.254','255.255.255.255',
}
_IP_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')


def _valid_ip(v: str) -> bool:
    parts = v.split('.')
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or str(int(p)) != p or int(p) > 255:
            return False
    return True


def _infer_spec(var_name: str, default_val: str, type_override: str | None = None) -> dict:
    """Infer the YANG type of a variable from its name and default value."""
    v     = str(default_val or '').strip()
    label = var_name.replace('_', ' ').title()
    if type_override:
        return {'type': type_override, 'label': label, 'default': v, 'required': True}
    if v in _VALID_MASKS:
        return {'type': 'ipv4-prefix-mask', 'label': label, 'default': v, 'required': True}
    if _valid_ip(v):
        return {'type': 'ipv4-address',     'label': label, 'default': v, 'required': True}
    if v.isdigit():
        n = int(v)
        t = 'uint8' if n <= 255 else 'uint16' if n <= 65535 else 'uint32'
        return {'type': t,      'label': label, 'default': v, 'required': True}
    return     {'type': 'string', 'label': label, 'default': v, 'required': True}


def _schema_to_yaml(vars_dict: dict) -> str:
    """Serialise a {varname: spec} dict to YANG-style YAML text."""
    lines = []
    for k, spec in vars_dict.items():
        lines.append(f'{k}:')
        lines.append(f'  type: {spec["type"]}')
        lines.append(f'  label: {spec["label"]}')
        if spec.get('default'):
            lines.append(f'  default: {spec["default"]}')
        lines.append(f'  required: {str(spec.get("required", True)).lower()}')
    return '\n'.join(lines)


# ── Integer type bounds ───────────────────────────────────────────────────────
_INT_BOUNDS: dict[str, tuple[int, int]] = {
    'uint8':  (0, 255),           'uint16': (0, 65535),
    'uint32': (0, 4294967295),    'uint64': (0, 9007199254740991),
    'int8':   (-128, 127),        'int16':  (-32768, 32767),
    'int32':  (-2147483648, 2147483647),
}


def render_var_form(schema_yaml: str) -> str:  # noqa: C901
    """
    Render a YANG-typed variable schema (YAML text) as ready-to-inject HTML
    form fields.

    Each field gets the right <input> or <select> widget plus native HTML5
    validation attributes (min/max/pattern/required) so the browser handles
    basic validation without any frontend JS type knowledge.

    Lives here so all YANG type logic stays in one place — next to
    _infer_spec and _schema_to_yaml rather than scattered across main.py.
    """
    import yaml
    from html import escape

    if not schema_yaml or not schema_yaml.strip():
        _log.info("[render_var_form] No schema — returning empty form")
        return '<p style="color:var(--muted);font-size:13px;">No variables — this service has no parameters.</p>'

    try:
        parsed = yaml.safe_load(schema_yaml) or {}
    except Exception:
        parsed = {}

    _log.info("[render_var_form] Rendering %d variable(s): %s", len(parsed), list(parsed.keys()))

    if not parsed:
        return ''

    _IP_PATTERN   = r'(\d{1,3}\.){3}\d{1,3}'

    def _range(spec: dict, type_: str) -> tuple:
        lo, hi = _INT_BOUNDS.get(type_, (None, None))
        r = str(spec.get('range', ''))
        m = re.match(r'(-?\d+)\s*\.\.\s*(-?\d+)', r)
        if m:
            lo, hi = int(m.group(1)), int(m.group(2))
        return lo, hi

    parts: list[str] = []

    for key, spec in parsed.items():
        # Support old flat format: "key: default_value"
        if not isinstance(spec, dict):
            spec = {'type': 'string', 'default': str(spec or '')}

        label    = escape(spec.get('label') or key.replace('_', ' ').title())
        default  = escape(str(spec.get('default', '')))
        type_    = spec.get('type', 'string')
        required = spec.get('required', True)
        hint     = spec.get('description', '')
        ek       = escape(key)
        et       = escape(type_)
        req_attr = 'required' if required else ''
        req_star = '<span style="color:var(--danger)">*</span>' if required else ''

        if type_ == 'boolean':
            t_sel = 'selected' if default == 'true'  else ''
            f_sel = 'selected' if default == 'false' else ''
            widget = (
                f'<select data-varkey="{ek}" data-type="{et}" {req_attr} '
                f'onchange="validateVarField(this)">'
                f'<option value="true" {t_sel}>true</option>'
                f'<option value="false" {f_sel}>false</option>'
                f'</select>'
            )

        elif type_ == 'enumeration' and spec.get('enum'):
            opts = ''.join(
                f'<option value="{escape(str(v))}"'
                f'{" selected" if escape(str(v)) == default else ""}>'
                f'{escape(str(v))}</option>'
                for v in spec['enum']
            )
            widget = (
                f'<select data-varkey="{ek}" data-type="{et}" {req_attr} '
                f'onchange="validateVarField(this)">{opts}</select>'
            )

        elif type_ in _INT_BOUNDS:
            lo, hi = _range(spec, type_)
            min_a  = f'min="{lo}"' if lo is not None else ''
            max_a  = f'max="{hi}"' if hi is not None else ''
            widget = (
                f'<input type="number" data-varkey="{ek}" data-type="{et}" '
                f'value="{default}" placeholder="{default or ek}" '
                f'{min_a} {max_a} step="1" {req_attr} '
                f'oninput="validateVarField(this)" />'
            )

        elif type_ == 'ipv4-address':
            widget = (
                f'<input type="text" data-varkey="{ek}" data-type="{et}" '
                f'value="{default}" placeholder="e.g. 192.168.1.1" '
                f'pattern="{_IP_PATTERN}" title="IPv4 address (e.g. 192.168.1.1)" '
                f'{req_attr} oninput="validateVarField(this)" />'
            )

        elif type_ == 'ipv4-prefix-mask':
            widget = (
                f'<input type="text" data-varkey="{ek}" data-type="{et}" '
                f'value="{default}" placeholder="e.g. 255.255.255.0" '
                f'pattern="{_IP_PATTERN}" title="Subnet mask (e.g. 255.255.255.0)" '
                f'{req_attr} oninput="validateVarField(this)" />'
            )

        else:  # string + anything unknown
            widget = (
                f'<input type="text" data-varkey="{ek}" data-type="{et}" '
                f'value="{default}" placeholder="{default or ek}" '
                f'{req_attr} oninput="validateVarField(this)" />'
            )

        hint_html = (
            f'<div style="font-size:11px;color:var(--muted);margin-bottom:4px;">'
            f'{escape(hint)}</div>'
        ) if hint else ''

        parts.append(
            f'<div class="form-group">'
            f'<label>{label} {req_star}</label>'
            f'{hint_html}'
            f'{widget}'
            f'<div class="var-field-error" '
            f'style="color:var(--danger);font-size:11px;margin-top:3px;display:none;"></div>'
            f'</div>'
        )

    return '\n'.join(parts)


class BaseDriver(ABC):
    """
    Every vendor NED must implement these methods.
    The core orchestrator calls only this interface — never vendor-specific code.
    """

    # ── NED Identity (set in each subclass) ──────────────────────────────
    NED_ID: str = ""          # e.g. "cisco-ios-cli-6.115"
    NED_VERSION: str = ""     # e.g. "6.115"
    PROTOCOL: str = "cli"     # "cli" | "netconf" | "restconf"

    # Feature flags — declare what this NED supports.
    # Common values: "rollback", "commit-queue", "live-status",
    #                "check-sync", "config-backup", "interface-list",
    #                "candidate-config"
    CAPABILITIES: tuple[str, ...] = ()

    # Netmiko device_type (CLI NEDs only)
    NETMIKO_DEVICE_TYPE: str = ""

    # Config commands by analysis type (pulled and stored/diffed)
    COMMANDS: dict[str, list[str]] = {}

    # Live-status (operational) commands — output is NOT configuration.
    # These pull real-time data: BGP sessions, interface counters, ARP tables.
    # Kept separate from COMMANDS so the orchestrator never diffs them like config.
    #
    # Keys are human-readable categories; values are CLI command lists.
    # Example:
    #   "bgp":        ["show bgp summary"],
    #   "interfaces": ["show interfaces"],
    #   "arp":        ["show arp"],
    #   "routes":     ["show ip route"],
    LIVE_STATUS_COMMANDS: dict[str, list[str]] = {}

    # ── Connection helpers ────────────────────────────────────────────────

    def get_connection_params(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 22,
        timeout: int = 30,
    ) -> dict:
        """
        Return the kwargs dict passed to Netmiko ConnectHandler.
        Override in subclass to add vendor-specific params (e.g. disabled_algorithms).
        """
        return {
            "device_type": self.NETMIKO_DEVICE_TYPE,
            "host": host,
            "username": username,
            "password": password,
            "port": port,
            "timeout": timeout,
            "session_log": None,
            "global_delay_factor": 1,
            "banner_timeout": 10,
            "auth_timeout": 10,
        }

    def get_commands(self, analysis_type: str) -> list[str]:
        """Return config command list for the given analysis type."""
        return self.COMMANDS.get(analysis_type, self.COMMANDS.get("status", []))

    def get_live_status_commands(self, category: str) -> list[str]:
        """
        Return operational command list for the given category.
        Returns empty list if category not supported by this NED.
        """
        return self.LIVE_STATUS_COMMANDS.get(category, [])

    def get_live_status_categories(self) -> list[str]:
        """Return all operational data categories this NED supports."""
        return list(self.LIVE_STATUS_COMMANDS.keys())

    def supports(self, capability: str) -> bool:
        """Check if this NED supports a given capability."""
        return capability in self.CAPABILITIES

    def ned_info(self) -> dict:
        """Return NED identity as a dict (for API responses)."""
        return {
            "ned_id": self.NED_ID,
            "version": self.NED_VERSION,
            "protocol": self.PROTOCOL,
            "capabilities": list(self.CAPABILITIES),
            "live_status_categories": self.get_live_status_categories(),
        }

    # ── Rollback support ──────────────────────────────────────────────────

    def rollback_command(self) -> Optional[str]:
        """
        Return a CLI command to roll back the last config change natively on
        the device (e.g. 'rollback configuration last 1' on IOS-XR).

        Return None if the device has no native rollback — the orchestrator
        will fall back to snapshot-based restore instead.
        """
        return None

    # ── Abstract interface — must be implemented ──────────────────────────

    @abstractmethod
    def test_command(self) -> str:
        """Single command used to verify connectivity (e.g. 'show version')."""
        ...

    @abstractmethod
    def save_config_command(self) -> Optional[str]:
        """
        Command to persist running config to startup config.
        Return None if the device saves automatically (e.g. FortiGate).
        """
        ...

    @abstractmethod
    def parse_version(self, raw_output: str) -> str:
        """
        Extract a short human-readable version/platform string
        from the output of test_command().
        """
        ...

    @abstractmethod
    def interfaces_command(self) -> str:
        """Command that lists all interfaces with their canonical names."""
        ...

    @abstractmethod
    def parse_interface_names(self, raw_output: str) -> list[str]:
        """
        Parse output of interfaces_command() and return a list of
        canonical interface names as the device knows them.
        e.g. ["GigabitEthernet1", "Loopback0", "Vlan10"]
        """
        ...

    def cli_to_template(self, raw_cli: str) -> dict:
        """
        Convert raw CLI config pasted by the user into a YANG-typed variable
        schema (YAML) + a Jinja2 service template.

        Each NED overrides this to parse its own CLI syntax and infer the
        correct YANG types (ipv4-address, uint32, string, etc.) for every
        extracted variable.

        Returns:
            {
                "schema":         str,   # YANG-style YAML variable definitions
                "template":       str,   # Jinja2 template string
                "variable_count": int,
            }

        Raise NotImplementedError if this NED does not support CLI conversion.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} ({self.NED_ID}) does not support CLI conversion yet."
        )
