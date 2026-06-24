"""
lld_models.py — LLD Compliance SQLAlchemy models + Pydantic schemas

LLD Template YAML format:
--------------------------
name: "Branch Router Standard"
description: "Minimum config standard for all branch routers"
checks:
  - id: ssh_v2
    description: "SSH version 2 must be enabled"
    type: must_contain
    value: "ip ssh version 2"

  - id: no_telnet
    description: "Telnet must be disabled on VTY lines"
    type: must_not_contain
    value: "transport input telnet"

  - id: ntp_configured
    description: "At least one NTP server must be configured"
    type: must_match_pattern
    pattern: "ntp server \\d+"

  - id: vty_ssh_only
    description: "VTY lines must restrict input to SSH"
    type: block_must_contain
    block: "line vty"
    value: "transport input ssh"

  - id: no_http_server
    description: "HTTP server must be disabled"
    type: must_not_match_pattern
    pattern: "^ip http server$"

Check types:
  must_contain          — exact line must exist anywhere in config
  must_not_contain      — exact line must NOT exist
  must_match_pattern    — regex must match at least one line
  must_not_match_pattern— regex must NOT match any line
  block_must_contain    — within a block starting with 'block', a child line must exist
  block_must_not_contain— within a block starting with 'block', a child line must NOT exist
"""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from pydantic import BaseModel

from backend.database import Base


# ─────────────────────────────────────────────
# SQLAlchemy Models
# ─────────────────────────────────────────────

class LLDTemplate(Base):
    __tablename__ = "lld_templates"

    id          = Column(Integer, primary_key=True, index=True)
    user_id     = Column(Integer, ForeignKey("users.id"), nullable=False)
    name        = Column(String, nullable=False)
    description = Column(String, default="")
    yaml_content = Column(Text, nullable=False, default="")
    created_at  = Column(DateTime, default=datetime.utcnow)
    updated_at  = Column(DateTime, default=datetime.utcnow)


class LLDCheckHistory(Base):
    __tablename__ = "lld_check_history"

    id          = Column(Integer, primary_key=True, index=True)
    user_id     = Column(Integer, ForeignKey("users.id"), nullable=False)
    template_id = Column(Integer, ForeignKey("lld_templates.id"), nullable=False)
    device_id   = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    passed      = Column(Integer, nullable=False)   # count
    failed      = Column(Integer, nullable=False)   # count
    total       = Column(Integer, nullable=False)   # count
    result_json = Column(Text, nullable=False, default="[]")
    checked_at  = Column(DateTime, default=datetime.utcnow)


# ─────────────────────────────────────────────
# Pydantic Schemas
# ─────────────────────────────────────────────

class LLDTemplateCreate(BaseModel):
    name: str
    description: str = ""
    yaml_content: str


class LLDTemplateUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    yaml_content: Optional[str] = None


class LLDTemplateResponse(BaseModel):
    id: int
    name: str
    description: str
    yaml_content: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class CheckResult(BaseModel):
    id: str
    description: str
    type: str
    status: str          # "pass" | "fail"
    detail: str = ""     # what was found / missing


class LLDComplianceResponse(BaseModel):
    template_id: int
    template_name: str
    device_id: int
    device_name: str
    passed: int
    failed: int
    total: int
    score_pct: float
    results: List[CheckResult]
    checked_at: str


class LLDCheckHistoryResponse(BaseModel):
    id: int
    template_id: int
    device_id: int
    passed: int
    failed: int
    total: int
    score_pct: float
    checked_at: datetime

    class Config:
        from_attributes = True
