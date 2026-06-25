"""
models.py — SQLAlchemy DB models + Pydantic request/response schemas
"""

import uuid
from datetime import datetime
from typing import Optional, List
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Boolean, UniqueConstraint, JSON
from sqlalchemy.orm import relationship
from pydantic import BaseModel, EmailStr

from backend.database import Base


# ─────────────────────────────────────────────
# SQLAlchemy Models (database tables)
# ─────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    devices = relationship("Device", back_populates="owner", cascade="all, delete")
    analysis_results = relationship("AnalysisResult", back_populates="user", cascade="all, delete")
    authgroups = relationship("Authgroup", backref="owner", cascade="all, delete")


class DeviceGroup(Base):
    __tablename__ = "device_groups"

    id          = Column(Integer, primary_key=True, index=True)
    user_id     = Column(Integer, ForeignKey("users.id"), nullable=False)
    name        = Column(String, nullable=False)
    description = Column(String, default="")
    created_at  = Column(DateTime, default=datetime.utcnow)

    devices = relationship("Device", back_populates="group")


class Authgroup(Base):
    """
    NSO-style authgroup: a named set of credentials reused across many devices.
    Instead of storing credentials per-device, store them once in an authgroup
    and reference it by name — matches exactly how NSO handles device credentials.
    """
    __tablename__ = "authgroups"

    id                 = Column(Integer, primary_key=True, index=True)
    user_id            = Column(Integer, ForeignKey("users.id"), nullable=False)
    name               = Column(String, nullable=False)           # e.g. "default", "datacenter", "wan"
    description        = Column(String, default="")
    default_username   = Column(String, nullable=False)
    encrypted_password = Column(String, nullable=False)
    enable_password    = Column(String, nullable=True)            # Cisco enable secret (optional)
    created_at         = Column(DateTime, default=datetime.utcnow)
    updated_at         = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    devices = relationship("Device", back_populates="authgroup_rel")


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (
        UniqueConstraint("user_id", "name", name="uq_device_name_per_user"),
        UniqueConstraint("user_id", "host", name="uq_device_host_per_user"),
    )

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=False)
    host = Column(String, nullable=False)
    port = Column(Integer, default=22)
    username = Column(String, nullable=False)
    encrypted_password = Column(String, nullable=False)
    device_type = Column(String, default="cisco_ios")

    # ── NED fields (NSO-inspired) ─────────────────────────────────────────
    # ned_id: the specific NED managing this device, e.g. "cisco-ios-cli-6.115"
    ned_id = Column(String, nullable=True, index=True)
    # authgroup: name of the Authgroup used for credentials (optional — device
    # can still carry its own username/password for backwards compat)
    authgroup = Column(String, nullable=True, default="default")
    # sync_state: last known sync status with the device
    #   "unknown"     — never checked
    #   "in-sync"     — last check-sync passed
    #   "out-of-sync" — last check-sync detected drift
    sync_state = Column(String, default="unknown")
    # platform: detected platform string from the device (e.g. "Cisco IOS-XE 17.3.1a")
    platform = Column(String, nullable=True)

    site = Column(String, default="")
    group_id = Column(Integer, ForeignKey("device_groups.id"), nullable=True)
    authgroup_id = Column(Integer, ForeignKey("authgroups.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, nullable=True)

    owner = relationship("User", back_populates="devices")
    group = relationship("DeviceGroup", back_populates="devices")
    authgroup_rel = relationship("Authgroup", back_populates="devices")
    analysis_results = relationship("AnalysisResult", back_populates="device", cascade="all, delete")
    config_snapshots  = relationship("ConfigSnapshot", back_populates="device", cascade="all, delete")
    sync_history      = relationship("SyncHistory",    back_populates="device", cascade="all, delete")


class ConfigSnapshot(Base):
    __tablename__ = "config_snapshots"

    id          = Column(Integer, primary_key=True, index=True)
    device_id   = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    config      = Column(Text, nullable=False)
    fetched_at  = Column(DateTime, default=datetime.utcnow)

    device = relationship("Device", back_populates="config_snapshots")


class SyncHistory(Base):
    __tablename__ = "sync_history"

    id             = Column(Integer, primary_key=True, index=True)
    device_id      = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    action         = Column(String, nullable=False)
    status         = Column(String, nullable=False)
    detail         = Column(Text, default="")
    timestamp      = Column(DateTime, default=datetime.utcnow)
    transaction_id = Column(String, nullable=True, index=True)

    device = relationship("Device", back_populates="sync_history")


class DeviceLock(Base):
    """
    Pessimistic device lock — prevents concurrent pushes by different engineers.
    Locks auto-expire after LOCK_TIMEOUT_MINUTES to avoid permanent deadlocks.
    """
    __tablename__ = "device_locks"

    id             = Column(Integer, primary_key=True, index=True)
    device_id      = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), unique=True, nullable=False)
    user_id        = Column(Integer, ForeignKey("users.id"), nullable=False)
    transaction_id = Column(String, nullable=False, default=lambda: str(uuid.uuid4()))
    locked_at      = Column(DateTime, default=datetime.utcnow)
    expires_at     = Column(DateTime, nullable=False)

    device = relationship("Device")
    user   = relationship("User")


class AnalysisResult(Base):
    __tablename__ = "analysis_results"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="SET NULL"), nullable=True)
    analysis_type = Column(String, nullable=False)
    prompt = Column(Text, nullable=False)
    result = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="analysis_results")
    device = relationship("Device", back_populates="analysis_results")


# ─────────────────────────────────────────────
# Pydantic Schemas
# ─────────────────────────────────────────────

class UserCreate(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: int
    email: str
    created_at: datetime

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class DeviceCreate(BaseModel):
    name: str
    host: str
    port: int = 22
    username: str
    password: str
    device_type: str = "cisco_ios"
    ned_id: Optional[str] = None        # e.g. "cisco-ios-cli-6.115"
    authgroup: Optional[str] = "default"
    site: str = ""
    group_id: Optional[int] = None


class DeviceUpdate(BaseModel):
    name: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    device_type: Optional[str] = None
    ned_id: Optional[str] = None
    authgroup: Optional[str] = None
    site: Optional[str] = None
    group_id: Optional[int] = None


class DeviceResponse(BaseModel):
    id: int
    name: str
    host: str
    port: int
    username: str
    device_type: str
    ned_id: Optional[str] = None
    authgroup: Optional[str] = None
    sync_state: str = "unknown"
    platform: Optional[str] = None
    site: str
    group_id: Optional[int] = None
    created_at: datetime
    last_seen: Optional[datetime]

    class Config:
        from_attributes = True


# ── Authgroup Schemas ─────────────────────────────────────────────────────────

class AuthgroupCreate(BaseModel):
    name: str
    description: str = ""
    default_username: str
    password: str
    enable_password: Optional[str] = None


class AuthgroupUpdate(BaseModel):
    description: Optional[str] = None
    default_username: Optional[str] = None
    password: Optional[str] = None
    enable_password: Optional[str] = None


class AuthgroupResponse(BaseModel):
    id: int
    name: str
    description: str
    default_username: str
    created_at: datetime

    class Config:
        from_attributes = True


# ── DeviceGroup Schemas ───────────────────────────────────────────────────────

class DeviceGroupCreate(BaseModel):
    name: str
    description: str = ""

class DeviceGroupUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None

class DeviceGroupResponse(BaseModel):
    id: int
    name: str
    description: str
    created_at: datetime

    class Config:
        from_attributes = True


class AnalysisRequest(BaseModel):
    analysis_type: str
    device_id: Optional[int] = None
    custom_input: Optional[str] = None


class AnalysisResponse(BaseModel):
    id: int
    analysis_type: str
    result: str
    created_at: datetime

    class Config:
        from_attributes = True


# ── NSO Sync Schemas ──────────────────────────────────────────────────────────

class ConfigSnapshotResponse(BaseModel):
    id: int
    device_id: int
    config: str
    fetched_at: datetime

    class Config:
        from_attributes = True


class SyncHistoryResponse(BaseModel):
    id: int
    device_id: int
    action: str
    status: str
    detail: str
    timestamp: datetime
    transaction_id: Optional[str] = None

    class Config:
        from_attributes = True


class DeviceLockResponse(BaseModel):
    device_id: int
    locked_by: str          # engineer's email
    transaction_id: str
    locked_at: datetime
    expires_at: datetime

    class Config:
        from_attributes = True


class CheckSyncResponse(BaseModel):
    status: str
    diff: str
    message: str


class ApplyConfigRequest(BaseModel):
    config: str          # full config text edited by user


class ApplyConfigResponse(BaseModel):
    status: str          # 'applied' | 'error' | 'no-change'
    lines_sent: int
    output: str
    message: str
    transaction_id: Optional[str] = None


# ── Services ──────────────────────────────────────────────────────────────────

class ServiceTemplate(Base):
    """
    A reusable service template — Jinja2 body + YAML variable schema.
    Customers create these themselves; no code changes needed.
    """
    __tablename__ = "service_templates"

    id            = Column(Integer, primary_key=True, index=True)
    user_id       = Column(Integer, ForeignKey("users.id"), nullable=False)
    name          = Column(String, nullable=False)
    description   = Column(String, default="")
    # NED this template targets — used to select the right CLI dialect
    # e.g. "fortinet-fortios-cli-1.0", "cisco-ios-cli-1.0"
    ned_id        = Column(String, nullable=True)
    # Jinja2 template that renders to CLI commands (one per line)
    template_body = Column(Text, nullable=False, default="")
    # YAML that defines variable schema:
    #   interface_name:
    #     label: Interface Name
    #     type: string
    #     default: Loopback0
    #     required: true
    variables_schema = Column(Text, nullable=False, default="")
    created_at    = Column(DateTime, default=datetime.utcnow)
    updated_at    = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    instances = relationship("ServiceInstance", back_populates="template", cascade="all, delete")


class ServiceInstance(Base):
    """A deployed service — template + resolved variable values on a device."""
    __tablename__ = "service_instances"

    id           = Column(Integer, primary_key=True, index=True)
    template_id  = Column(Integer, ForeignKey("service_templates.id"), nullable=False)
    device_id    = Column(Integer, ForeignKey("devices.id", ondelete="RESTRICT"), nullable=True)
    user_id      = Column(Integer, ForeignKey("users.id"), nullable=False)
    # JSON-encoded dict of variable values used at deploy time
    variable_values = Column(Text, nullable=False, default="{}")
    status       = Column(String, default="deployed")   # deployed | error
    output       = Column(Text, default="")
    deployed_at  = Column(DateTime, default=datetime.utcnow)

    template = relationship("ServiceTemplate", back_populates="instances")


# ── Service Pydantic Schemas ──────────────────────────────────────────────────

class ServiceTemplateCreate(BaseModel):
    name: str
    description: str = ""
    ned_id: Optional[str] = None
    template_body: str
    variables_schema: str   # raw YAML text


class ServiceTemplateUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    ned_id: Optional[str] = None
    template_body: Optional[str] = None
    variables_schema: Optional[str] = None


class ServiceTemplateResponse(BaseModel):
    id: int
    name: str
    description: str
    ned_id: Optional[str] = None
    template_body: str
    variables_schema: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ServicePreviewRequest(BaseModel):
    variable_values: dict   # { "interface_name": "Loopback10", ... }


class ServicePreviewResponse(BaseModel):
    rendered: str           # rendered CLI lines joined by \n
    lines: list[str]        # individual commands


class ServiceDeployRequest(BaseModel):
    device_id: int
    variable_values: dict


class ServiceDeployResponse(BaseModel):
    status: str
    lines_sent: int
    output: str
    message: str
    instance_id: int
    transaction_id: Optional[str] = None


class ServiceDryRunRequest(BaseModel):
    device_id: int
    variable_values: dict


class DryRunLine(BaseModel):
    line: str
    indent: int          # 0 = top-level, 1 = child
    status: str          # "new" | "exists" | "parent"


class ServiceDryRunResponse(BaseModel):
    lines: list[DryRunLine]
    new_count: int
    exists_count: int
    device_name: str


# ── Network as Code — State Management ───────────────────────────────────────

class StateDeclaration(Base):
    """
    Desired state declaration — the authoritative intent for a service on a device.
    This is what the network *should* look like. Source of truth can be the UI or a
    git-managed YAML file. NetFabric compares this against the live device to
    compute plans and detect drift.

    Status lifecycle:
        pending   — declared but never applied
        applied   — last apply succeeded; known_state_hash matches desired
        drifted   — device diverged from known state (manual change detected)
        error     — last apply failed
    """
    __tablename__ = "state_declarations"

    id                  = Column(Integer, primary_key=True, index=True)
    user_id             = Column(Integer, ForeignKey("users.id"), nullable=False)
    name                = Column(String, nullable=False)          # human label, e.g. "lan-to-wan-policy"
    service_template_id = Column(Integer, ForeignKey("service_templates.id"), nullable=False)
    device_id           = Column(Integer, ForeignKey("devices.id", ondelete="RESTRICT"), nullable=False)
    # Desired variable values (JSON) — the intent
    variables           = Column(JSON, nullable=False, default=dict)
    # Source: 'ui' (created via UI) or 'git' (imported from YAML)
    source              = Column(String, default="ui")
    # Path in git repo when source='git', e.g. "services/lan-to-wan.yaml"
    git_path            = Column(String, nullable=True)
    # Status of this declaration
    status              = Column(String, default="pending")       # pending|applied|drifted|error
    # Hash of variables at last successful apply — used to detect desired-state changes
    last_applied_hash   = Column(String, nullable=True)
    # Rendered CLI lines that were last successfully applied (for drift comparison)
    last_applied_config = Column(Text, nullable=True)
    last_plan_at        = Column(DateTime, nullable=True)
    last_applied_at     = Column(DateTime, nullable=True)
    created_at          = Column(DateTime, default=datetime.utcnow)
    updated_at          = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user     = relationship("User")
    template = relationship("ServiceTemplate")
    device   = relationship("Device")
    plans    = relationship("StatePlan", back_populates="declaration", cascade="all, delete")


class StatePlan(Base):
    """
    A computed plan — the diff between desired state and the live device.
    Plans are immutable once created; applying a plan creates a new one on next run.

    Status:
        pending   — computed, not yet applied
        applied   — was used to drive an apply operation
        superseded — a newer plan exists for this declaration
        failed    — apply attempt failed
    """
    __tablename__ = "state_plans"

    id             = Column(Integer, primary_key=True, index=True)
    declaration_id = Column(Integer, ForeignKey("state_declarations.id"), nullable=False)
    user_id        = Column(Integer, ForeignKey("users.id"), nullable=False)
    # Structured diff data
    lines_to_add   = Column(JSON, default=list)   # config lines not yet on device
    lines_existing = Column(JSON, default=list)   # lines already present (no-op)
    # Human-readable summary
    summary        = Column(Text, default="")
    # Status
    status         = Column(String, default="pending")  # pending|applied|superseded|failed
    # If applied: the deploy output and transaction id
    apply_output   = Column(Text, nullable=True)
    transaction_id = Column(String, nullable=True)
    created_at     = Column(DateTime, default=datetime.utcnow)
    applied_at     = Column(DateTime, nullable=True)

    declaration = relationship("StateDeclaration", back_populates="plans")
    user        = relationship("User")


# ── State Pydantic Schemas ────────────────────────────────────────────────────

class StateDeclarationCreate(BaseModel):
    name: str
    service_template_id: int
    device_id: int
    variables: dict
    source: str = "ui"
    git_path: Optional[str] = None


class StateDeclarationUpdate(BaseModel):
    name: Optional[str] = None
    variables: Optional[dict] = None


class StateDeclarationResponse(BaseModel):
    id: int
    name: str
    service_template_id: int
    device_id: int
    variables: dict
    source: str
    git_path: Optional[str] = None
    status: str
    last_plan_at: Optional[datetime] = None
    last_applied_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    # Enriched fields (joined)
    template_name: Optional[str] = None
    device_name: Optional[str] = None

    class Config:
        from_attributes = True


class StatePlanResponse(BaseModel):
    id: int
    declaration_id: int
    lines_to_add: List[str]
    lines_existing: List[str]
    summary: str
    status: str
    apply_output: Optional[str] = None
    transaction_id: Optional[str] = None
    created_at: datetime
    applied_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class StateApplyResponse(BaseModel):
    status: str          # applied | no-change | error
    plan_id: int
    lines_sent: int
    output: str
    message: str
    transaction_id: Optional[str] = None


class StateImportItem(BaseModel):
    """Single YAML declaration item for bulk import."""
    name: str
    service_template: str   # template name (looked up by name)
    device: str             # device name (looked up by name)
    variables: dict
    git_path: Optional[str] = None


class StateImportRequest(BaseModel):
    declarations: List[StateImportItem]


class StateImportResponse(BaseModel):
    created: int
    updated: int
    errors: List[str]
