"""
config_loader.py — Network as Code file loader

Reads YAML files from the mounted config/ directory and upserts them into
the database. Called on startup and via POST /api/reload.

Directory layout:
  config/
    services/        ← Jinja2 service templates + variable schemas
      *.yaml
    instances/       ← Variable values for a specific device (ready to deploy)
      *.yaml
    lld/             ← LLD compliance check templates
      *.yaml
"""

import os
import logging
import yaml
from pathlib import Path
from datetime import datetime
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

CONFIG_DIR = Path(os.environ.get("CONFIG_DIR", "/app/config"))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_yaml_files(subdir: str) -> list[tuple[Path, dict]]:
    """Return (path, parsed_dict) for every *.yaml in config/<subdir>/."""
    d = CONFIG_DIR / subdir
    if not d.exists():
        return []
    results = []
    for f in sorted(d.glob("*.yaml")):
        try:
            with open(f) as fh:
                data = yaml.safe_load(fh)
            if isinstance(data, dict):
                results.append((f, data))
            else:
                logger.warning(f"[config_loader] Skipping {f}: not a YAML mapping")
        except Exception as e:
            logger.error(f"[config_loader] Failed to parse {f}: {e}")
    return results


# ── Service templates ─────────────────────────────────────────────────────────

def sync_services(db: Session, user_id: int) -> dict:
    """
    Upsert service templates from config/services/*.yaml.

    Expected file format:
      name: FW Policy FortiGate
      ned_id: fortinet-fortios-cli-1.0
      description: FortiGate firewall policy   # optional
      variables:                               # variable schema (YAML)
        POLICY_NAME:
          label: Policy Name
          type: string
          required: true
        SRC_INTF:
          label: Source Interface
          type: string
          default: port2
      template: |
        config firewall policy
          edit 0
          set name {{ POLICY_NAME }}
          ...
          next
        end
    """
    from backend.models import ServiceTemplate

    files = _load_yaml_files("services")
    created = updated = errors = 0

    for path, data in files:
        name = data.get("name") or path.stem
        try:
            body   = data.get("template", "")
            schema = data.get("variables", {})
            # Serialise schema back to YAML text (matches what the UI stores)
            schema_text = yaml.dump(schema, default_flow_style=False) if schema else ""
            ned_id = data.get("ned_id")
            desc   = data.get("description", "")

            existing = db.query(ServiceTemplate).filter(
                ServiceTemplate.name == name,
                ServiceTemplate.user_id == user_id,
            ).first()

            if existing:
                existing.template_body    = body
                existing.variables_schema = schema_text
                existing.ned_id           = ned_id
                existing.description      = desc
                existing.updated_at       = datetime.utcnow()
                updated += 1
                logger.info(f"[config_loader] Updated service: {name}")
            else:
                db.add(ServiceTemplate(
                    user_id          = user_id,
                    name             = name,
                    description      = desc,
                    ned_id           = ned_id,
                    template_body    = body,
                    variables_schema = schema_text,
                ))
                created += 1
                logger.info(f"[config_loader] Created service: {name}")

        except Exception as e:
            logger.error(f"[config_loader] Error syncing service {name}: {e}")
            errors += 1

    if files:
        db.commit()
    return {"created": created, "updated": updated, "errors": errors, "files": len(files)}


# ── Service instances ─────────────────────────────────────────────────────────

def sync_instances(db: Session, user_id: int) -> dict:
    """
    Upsert service instances (variable values) from config/instances/*.yaml.
    Instances are stored as StateDeclarations so they can be planned/applied.

    Expected file format:
      name: lan-to-wan
      service: FW Policy FortiGate   # must match a service template name
      device: FG1                    # must match a device name
      variables:
        POLICY_NAME: LAN-to-WAN
        SRC_INTF: port2
        DST_INTF: port1
        SERVICE: HTTPS
    """
    from backend.models import ServiceTemplate, Device, StateDeclaration

    files = _load_yaml_files("instances")
    created = updated = errors = 0

    for path, data in files:
        name = data.get("name") or path.stem
        try:
            svc_name  = data.get("service", "")
            dev_name  = data.get("device", "")
            variables = data.get("variables", {})

            tmpl = db.query(ServiceTemplate).filter(
                ServiceTemplate.name == svc_name,
                ServiceTemplate.user_id == user_id,
            ).first()
            if not tmpl:
                logger.warning(f"[config_loader] Instance {name}: service '{svc_name}' not found — skipping")
                errors += 1
                continue

            dev = db.query(Device).filter(
                Device.name == dev_name,
                Device.user_id == user_id,
            ).first()
            if not dev:
                logger.warning(f"[config_loader] Instance {name}: device '{dev_name}' not found — skipping")
                errors += 1
                continue

            existing = db.query(StateDeclaration).filter(
                StateDeclaration.name == name,
                StateDeclaration.user_id == user_id,
            ).first()

            if existing:
                existing.variables           = variables
                existing.service_template_id = tmpl.id
                existing.device_id           = dev.id
                existing.source              = "git"
                existing.git_path            = str(path.relative_to(CONFIG_DIR))
                if existing.status == "applied":
                    existing.status = "pending"
                updated += 1
                logger.info(f"[config_loader] Updated instance: {name}")
            else:
                db.add(StateDeclaration(
                    user_id             = user_id,
                    name                = name,
                    service_template_id = tmpl.id,
                    device_id           = dev.id,
                    variables           = variables,
                    source              = "git",
                    git_path            = str(path.relative_to(CONFIG_DIR)),
                    status              = "pending",
                ))
                created += 1
                logger.info(f"[config_loader] Created instance: {name}")

        except Exception as e:
            logger.error(f"[config_loader] Error syncing instance {name}: {e}")
            errors += 1

    if files:
        db.commit()
    return {"created": created, "updated": updated, "errors": errors, "files": len(files)}


# ── LLD templates ─────────────────────────────────────────────────────────────

def sync_lld(db: Session, user_id: int) -> dict:
    """
    Upsert LLD compliance templates from config/lld/*.yaml.
    The entire file is stored as yaml_content (matches UI behaviour).

    Expected file format:
      name: FortiGate Security Baseline
      description: Baseline compliance checks for all FortiGate devices
      checks:
        - id: ntp-sync
          description: NTP sync must be enabled
          pattern: "set ntpsync enable"
          severity: critical
        - id: admin-timeout
          description: Admin idle timeout <= 5 minutes
          pattern: "set admintimeout [1-5]"
          severity: warning
    """
    from backend.lld_models import LLDTemplate

    files = _load_yaml_files("lld")
    created = updated = errors = 0

    for path, data in files:
        name = data.get("name") or path.stem
        try:
            desc     = data.get("description", "")
            # Store raw YAML text as yaml_content
            with open(path) as fh:
                raw = fh.read()

            existing = db.query(LLDTemplate).filter(
                LLDTemplate.name == name,
                LLDTemplate.user_id == user_id,
            ).first()

            if existing:
                existing.description = desc
                existing.yaml_content = raw
                existing.updated_at   = datetime.utcnow()
                updated += 1
                logger.info(f"[config_loader] Updated LLD: {name}")
            else:
                db.add(LLDTemplate(
                    user_id      = user_id,
                    name         = name,
                    description  = desc,
                    yaml_content = raw,
                ))
                created += 1
                logger.info(f"[config_loader] Created LLD: {name}")

        except Exception as e:
            logger.error(f"[config_loader] Error syncing LLD {name}: {e}")
            errors += 1

    if files:
        db.commit()
    return {"created": created, "updated": updated, "errors": errors, "files": len(files)}


# ── Main entry point ──────────────────────────────────────────────────────────

def reload_all(db: Session, user_id: int) -> dict:
    """Sync all config file types. Returns a summary dict."""
    logger.info(f"[config_loader] Reloading config files from {CONFIG_DIR} for user {user_id}")
    return {
        "services":  sync_services(db, user_id),
        "instances": sync_instances(db, user_id),
        "lld":       sync_lld(db, user_id),
    }
