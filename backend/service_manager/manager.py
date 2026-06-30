"""
service_manager/manager.py — NetFabric Service Manager

The Service Manager is the orchestration layer between the abstract service
definition and the vendor-specific ND (Network Driver) layer.

Responsibilities:
  - Resolve which ND template to use for a given target device
  - Render the Jinja2 template with the supplied variable values
  - Delegate config push / diff to the appropriate ND driver
  - Merge variable schemas when multiple NDs contribute to one service

Architecture:
  Service (generic, multi-vendor)
    └─ nd_templates: {nd_id: jinja2_template}   ← one per supported ND
    └─ variables_schema: YANG YAML              ← shared across all NDs

  ServiceManager.deploy(service, device, var_values)
    ├─ resolves nd_id from device
    ├─ picks nd_templates[nd_id]
    ├─ renders Jinja2 → CLI lines
    └─ calls ND driver to push config

Inspired by Cisco NSO's service manager / RFS (Resource Facing Service) model.
"""

import logging
import re
from typing import TYPE_CHECKING

import yaml
from jinja2 import Environment, StrictUndefined, UndefinedError

from backend.drivers import get_driver
from backend.drivers.base import validate_var_value

if TYPE_CHECKING:
    from backend.models import ServiceTemplate, Device

_log = logging.getLogger(__name__)


class ServiceManagerError(Exception):
    """Raised when the Service Manager cannot fulfill a request."""


class ServiceManager:
    """
    Single entry point for all service operations.

    Usage (from FastAPI endpoints):
        sm = ServiceManager()
        cli   = sm.render(service, device, var_values)
        diff  = sm.dry_run(service, device, var_values, current_config)
        errors = sm.validate(service, device, var_values)
    """

    # ── Template resolution ───────────────────────────────────────────────

    def resolve_template(self, service: "ServiceTemplate", nd_id: str) -> str:
        """
        Return the Jinja2 template for the given ND.

        Priority:
          1. nd_templates[nd_id]       — new multi-vendor store
          2. template_body (legacy)    — old single-ND field, only if ned_id matches
          3. Raise ServiceManagerError — no template found for this ND
        """
        nd_templates: dict = service.nd_templates or {}

        if nd_id in nd_templates:
            _log.debug("[SM] resolved nd_template for nd=%s svc=%s", nd_id, service.name)
            return nd_templates[nd_id]

        # Legacy fallback: single-ND service
        if service.template_body and (not service.ned_id or service.ned_id == nd_id):
            _log.debug("[SM] using legacy template_body for nd=%s svc=%s", nd_id, service.name)
            return service.template_body

        supported = list(nd_templates.keys()) or ([service.ned_id] if service.ned_id else [])
        raise ServiceManagerError(
            f"Service '{service.name}' has no template for ND '{nd_id}'. "
            f"Supported NDs: {supported or ['none configured']}"
        )

    # ── Rendering ─────────────────────────────────────────────────────────

    def render(self, service: "ServiceTemplate", device: "Device", var_values: dict) -> str:
        """
        Render the service template for the given device using var_values.
        Returns rendered CLI text (multi-line string).
        """
        nd_id    = device.ned_id or ''
        template = self.resolve_template(service, nd_id)

        _log.info(
            "[SM] render: svc=%r nd=%r device=%r vars=%s",
            service.name, nd_id, device.name, list(var_values.keys()),
        )

        try:
            env = Environment(undefined=StrictUndefined, keep_trailing_newline=True)
            return env.from_string(template).render(**var_values)
        except UndefinedError as e:
            raise ServiceManagerError(f"Template variable error: {e}") from e

    # ── Dry run / diff ────────────────────────────────────────────────────

    def dry_run(
        self,
        service: "ServiceTemplate",
        device: "Device",
        var_values: dict,
        current_config: str,
    ) -> dict:
        """
        Render the template and diff it against the device's current config.

        Returns:
            {
                "rendered":      str,   # full rendered CLI
                "lines_to_add":  list,  # lines not yet on device
                "lines_exist":   list,  # lines already present
            }
        """
        rendered = self.render(service, device, var_values)
        driver   = get_driver(device.ned_id or '')
        current  = driver.normalize_for_diff(current_config)
        existing = {l.strip() for l in current.splitlines() if l.strip()}

        to_add, exist = [], []
        for line in rendered.splitlines():
            s = line.strip()
            if not s:
                continue
            (exist if s in existing else to_add).append(line)

        _log.info(
            "[SM] dry_run: svc=%r device=%r — %d to add, %d already exist",
            service.name, device.name, len(to_add), len(exist),
        )
        return {"rendered": rendered, "lines_to_add": to_add, "lines_exist": exist}

    # ── Validation ────────────────────────────────────────────────────────

    def validate(
        self,
        service: "ServiceTemplate",
        device: "Device",
        var_values: dict,
    ) -> dict[str, str | None]:
        """
        Validate variable values through the target device's ND driver.

        The ND driver owns the type rules (validate_vars can be overridden
        per vendor for device-specific constraints).
        Returns {field: error_message_or_None}.
        """
        nd_id  = device.ned_id or ''
        driver = get_driver(nd_id)
        _log.info("[SM] validate: svc=%r nd=%r fields=%s", service.name, nd_id, list(var_values.keys()))
        return driver.validate_vars(var_values, service.variables_schema or '')

    # ── Schema merge (used when adding a new ND template to a service) ────

    @staticmethod
    def merge_schemas(base_yaml: str, new_yaml: str) -> str:
        """
        Merge two YANG YAML schemas. New variables are added; existing ones
        keep their base definition (base wins on conflict to preserve user edits).
        """
        try:
            base = yaml.safe_load(base_yaml or '') or {}
        except Exception:
            base = {}
        try:
            new = yaml.safe_load(new_yaml or '') or {}
        except Exception:
            new = {}

        merged = dict(new)   # start with new
        merged.update(base)  # base wins on conflict
        if not merged:
            return ''

        lines = []
        for k, spec in merged.items():
            if not isinstance(spec, dict):
                spec = {'type': 'string', 'default': str(spec or '')}
            lines.append(f'{k}:')
            for field in ('type', 'label', 'default', 'required', 'range', 'enum', 'description'):
                if field in spec:
                    val = spec[field]
                    if isinstance(val, list):
                        lines.append(f'  {field}:')
                        for item in val:
                            lines.append(f'    - {item}')
                    else:
                        lines.append(f'  {field}: {val}')
        return '\n'.join(lines)


# Module-level singleton
service_manager = ServiceManager()
