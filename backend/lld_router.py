"""
lld_router.py — LLD Compliance API routes

Prefix: /api/lld

Templates:
  GET    /api/lld/templates              — list templates
  POST   /api/lld/templates              — create template
  GET    /api/lld/templates/{id}         — get template
  PUT    /api/lld/templates/{id}         — update template
  DELETE /api/lld/templates/{id}         — delete template

Compliance:
  POST   /api/lld/templates/{id}/check/{device_id}  — run compliance check
  GET    /api/lld/history                            — check history
"""

import json
import logging
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.auth import get_current_user, decrypt_password
from backend.models import User, Device
from backend.lld_models import (
    LLDTemplate, LLDCheckHistory,
    LLDTemplateCreate, LLDTemplateUpdate, LLDTemplateResponse,
    LLDComplianceResponse, LLDCheckHistoryResponse, CheckResult,
)
from backend.lld_engine import run_compliance
from backend import device_connector

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/lld", tags=["lld"])


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _get_template(template_id: int, user_id: int, db: Session) -> LLDTemplate:
    t = db.query(LLDTemplate).filter(
        LLDTemplate.id == template_id,
        LLDTemplate.user_id == user_id,
    ).first()
    if not t:
        raise HTTPException(status_code=404, detail="LLD template not found")
    return t


def _get_device(device_id: int, user_id: int, db: Session) -> Device:
    d = db.query(Device).filter(
        Device.id == device_id,
        Device.user_id == user_id,
    ).first()
    if not d:
        raise HTTPException(status_code=404, detail="Device not found")
    return d


# ─────────────────────────────────────────────
# Template CRUD
# ─────────────────────────────────────────────

@router.get("/templates", response_model=List[LLDTemplateResponse])
def list_templates(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return (
        db.query(LLDTemplate)
        .filter(LLDTemplate.user_id == current_user.id)
        .order_by(LLDTemplate.created_at.desc())
        .all()
    )


@router.post("/templates", response_model=LLDTemplateResponse, status_code=201)
def create_template(
    payload: LLDTemplateCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    t = LLDTemplate(user_id=current_user.id, **payload.model_dump())
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


@router.get("/templates/{template_id}", response_model=LLDTemplateResponse)
def get_template(
    template_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return _get_template(template_id, current_user.id, db)


@router.put("/templates/{template_id}", response_model=LLDTemplateResponse)
def update_template(
    template_id: int,
    payload: LLDTemplateUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    t = _get_template(template_id, current_user.id, db)
    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(t, field, value)
    t.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(t)
    return t


@router.delete("/templates/{template_id}", status_code=204)
def delete_template(
    template_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    t = _get_template(template_id, current_user.id, db)
    db.delete(t)
    db.commit()


# ─────────────────────────────────────────────
# Compliance Check
# ─────────────────────────────────────────────

@router.post("/templates/{template_id}/check/{device_id}", response_model=LLDComplianceResponse)
def run_compliance_check(
    template_id: int,
    device_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Pull running config from device and check it against the LLD template.
    Saves result to history.
    """
    template = _get_template(template_id, current_user.id, db)
    device   = _get_device(device_id, current_user.id, db)

    # Pull running config from device
    plain_password = decrypt_password(device.encrypted_password)
    pull = device_connector.pull_device_data(
        host=device.host,
        username=device.username,
        password=plain_password,
        device_type=device.device_type,
        port=device.port,
        analysis_type="config_backup",
    )
    if not pull["success"]:
        raise HTTPException(status_code=502, detail=f"Could not connect to device: {pull['error']}")

    running_config = pull["data"]
    # Strip section headers added by pull_device_data
    if running_config.startswith("### "):
        running_config = "\n".join(running_config.split("\n")[1:]).strip()

    # Run compliance engine
    raw_results = run_compliance(template.yaml_content, running_config)

    passed = sum(1 for r in raw_results if r["status"] == "pass")
    failed = sum(1 for r in raw_results if r["status"] == "fail")
    total  = len(raw_results)
    score  = round(passed / total * 100, 1) if total > 0 else 0.0

    # Save to history
    history = LLDCheckHistory(
        user_id=current_user.id,
        template_id=template_id,
        device_id=device_id,
        passed=passed,
        failed=failed,
        total=total,
        result_json=json.dumps(raw_results),
    )
    db.add(history)
    device.last_seen = datetime.utcnow()
    db.commit()

    logger.info(f"LLD check: template={template.name} device={device.name} score={score}%")

    return LLDComplianceResponse(
        template_id=template_id,
        template_name=template.name,
        device_id=device_id,
        device_name=device.name,
        passed=passed,
        failed=failed,
        total=total,
        score_pct=score,
        results=[CheckResult(**r) for r in raw_results],
        checked_at=datetime.now(timezone.utc).isoformat(),
    )


# ─────────────────────────────────────────────
# History
# ─────────────────────────────────────────────

@router.get("/history", response_model=List[LLDCheckHistoryResponse])
def check_history(
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(LLDCheckHistory)
        .filter(LLDCheckHistory.user_id == current_user.id)
        .order_by(LLDCheckHistory.checked_at.desc())
        .limit(limit)
        .all()
    )
    result = []
    for r in rows:
        result.append(LLDCheckHistoryResponse(
            id=r.id,
            template_id=r.template_id,
            device_id=r.device_id,
            passed=r.passed,
            failed=r.failed,
            total=r.total,
            score_pct=round(r.passed / r.total * 100, 1) if r.total > 0 else 0.0,
            checked_at=r.checked_at,
        ))
    return result
