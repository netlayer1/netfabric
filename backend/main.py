"""
main.py — FastAPI application
Network AI Orchestrator — SaaS MVP

Routes:
  GET  /health                            — health check
  POST /api/auth/register                 — create account
  POST /api/auth/login                    — get JWT token
  GET  /api/auth/me                       — current user info

  GET  /api/neds                          — list available NEDs
  GET  /api/neds/{ned_id}                 — NED details + capabilities

  GET  /api/authgroups                    — list authgroups
  POST /api/authgroups                    — create authgroup
  PUT  /api/authgroups/{id}               — update authgroup
  DELETE /api/authgroups/{id}             — delete authgroup

  GET  /api/devices                       — list devices
  POST /api/devices                       — add device
  GET  /api/devices/{id}                  — get device
  PUT  /api/devices/{id}                  — update device
  DELETE /api/devices/{id}               — delete device
  POST /api/devices/{id}/test             — test SSH connectivity
  GET  /api/devices/{id}/status           — pull live status (operational data)
  GET  /api/devices/{id}/live-status/{cat} — pull specific live-status category
  POST /api/devices/{id}/sync-from        — pull device config into orchestrator (NSO: sync-from)
  POST /api/devices/{id}/sync-to          — push orchestrator config to device (NSO: sync-to)
  POST /api/devices/{id}/compare-config   — diff orchestrator vs live device (NSO: compare-config)

  POST /api/analysis                      — run AI analysis
  GET  /api/analysis/history              — analysis history

  GET  /                                  — serve frontend
"""

import os
import uuid
import logging
from contextlib import asynccontextmanager
from dotenv import load_dotenv
load_dotenv()
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from backend.database import engine, get_db, Base
import difflib
from backend.config_diff import generate_delta, summarise_delta, resolve_config
from backend.drivers import get_driver
from backend.ned_registry import NED_REGISTRY, get_ned_metadata, list_neds, ned_id_from_netmiko_type
import json
import yaml
from jinja2 import Environment, StrictUndefined, UndefinedError, TemplateSyntaxError

from backend.models import (
    User, Device, AnalysisResult, ConfigSnapshot, SyncHistory,
    DeviceGroup, DeviceLock, Authgroup,
    UserCreate, UserResponse, TokenResponse,
    DeviceCreate, DeviceUpdate, DeviceResponse,
    AuthgroupCreate, AuthgroupUpdate, AuthgroupResponse,
    DeviceGroupCreate, DeviceGroupUpdate, DeviceGroupResponse,
    AnalysisRequest, AnalysisResponse,
    ConfigSnapshotResponse, SyncHistoryResponse, CheckSyncResponse,
    ApplyConfigRequest, ApplyConfigResponse,
    DeviceLockResponse,
    ServiceTemplate, ServiceInstance,
    ServiceTemplateCreate, ServiceTemplateUpdate, ServiceTemplateResponse,
    ServicePreviewRequest, ServicePreviewResponse,
    ServiceDeployRequest, ServiceDeployResponse,
    ServiceDryRunRequest, ServiceDryRunResponse, DryRunLine,
)
from backend.auth import (
    hash_password, verify_password,
    create_access_token, get_current_user,
    encrypt_password, decrypt_password,
)
from backend import device_connector, api_client
from backend.ipam_models import Vlan, Subnet, IPAddress
from backend.ipam_router import router as ipam_router
from backend.lld_models import LLDTemplate, LLDCheckHistory
from backend.lld_router import router as lld_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# App startup — create DB tables
# ─────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created/verified")
    yield

app = FastAPI(
    title="Network AI Orchestrator",
    version="1.0.0",
    description="AI-powered network management for MSP clients",
    lifespan=lifespan,
)

app.include_router(ipam_router)
app.include_router(lld_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # Tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend static files
if os.path.exists("frontend"):
    app.mount("/static", StaticFiles(directory="frontend"), name="static")


# ─────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


# ─────────────────────────────────────────────
# NED Routes  (NSO-inspired)
# ─────────────────────────────────────────────

@app.get("/api/neds")
def list_ned_registry():
    """
    Return all registered NEDs with their metadata.
    Equivalent to NSO's 'show packages' — tells you what device types
    this orchestrator can manage and what each supports.
    """
    return {"neds": list_neds()}


@app.get("/api/neds/{ned_id:path}")
def get_ned(ned_id: str):
    """Return details for a specific NED including capabilities and live-status categories."""
    meta = get_ned_metadata(ned_id)
    if not meta:
        raise HTTPException(status_code=404, detail=f"NED '{ned_id}' not registered")
    driver = get_driver(ned_id)
    return {
        **meta.to_dict(),
        "live_status_categories": driver.get_live_status_categories(),
    }


# ─────────────────────────────────────────────
# Authgroup Routes  (NSO-inspired)
# ─────────────────────────────────────────────

@app.get("/api/authgroups", response_model=List[AuthgroupResponse])
def list_authgroups(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all authgroups for the current user."""
    return db.query(Authgroup).filter(Authgroup.user_id == current_user.id).all()


@app.post("/api/authgroups", response_model=AuthgroupResponse, status_code=201)
def create_authgroup(
    payload: AuthgroupCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Create a named authgroup.
    Devices that share the same credentials can reference this authgroup
    by name instead of each storing their own username/password.
    """
    existing = db.query(Authgroup).filter(
        Authgroup.user_id == current_user.id,
        Authgroup.name == payload.name,
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Authgroup '{payload.name}' already exists")

    ag = Authgroup(
        user_id=current_user.id,
        name=payload.name,
        description=payload.description,
        default_username=payload.default_username,
        encrypted_password=encrypt_password(payload.password),
        enable_password=encrypt_password(payload.enable_password) if payload.enable_password else None,
    )
    db.add(ag)
    db.commit()
    db.refresh(ag)
    return ag


@app.put("/api/authgroups/{ag_id}", response_model=AuthgroupResponse)
def update_authgroup(
    ag_id: int,
    payload: AuthgroupUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    ag = db.query(Authgroup).filter(
        Authgroup.id == ag_id,
        Authgroup.user_id == current_user.id,
    ).first()
    if not ag:
        raise HTTPException(status_code=404, detail="Authgroup not found")
    if payload.description is not None:
        ag.description = payload.description
    if payload.default_username is not None:
        ag.default_username = payload.default_username
    if payload.password is not None:
        ag.encrypted_password = encrypt_password(payload.password)
    if payload.enable_password is not None:
        ag.enable_password = encrypt_password(payload.enable_password)
    db.commit()
    db.refresh(ag)
    return ag


@app.delete("/api/authgroups/{ag_id}", status_code=204)
def delete_authgroup(
    ag_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    ag = db.query(Authgroup).filter(
        Authgroup.id == ag_id,
        Authgroup.user_id == current_user.id,
    ).first()
    if not ag:
        raise HTTPException(status_code=404, detail="Authgroup not found")
    db.delete(ag)
    db.commit()


# ─────────────────────────────────────────────
# Device Group Routes
# ─────────────────────────────────────────────

@app.get("/api/device-groups", response_model=List[DeviceGroupResponse])
def list_device_groups(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return db.query(DeviceGroup).filter(DeviceGroup.user_id == current_user.id).all()


@app.post("/api/device-groups", response_model=DeviceGroupResponse, status_code=201)
def create_device_group(
    payload: DeviceGroupCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    group = DeviceGroup(
        user_id=current_user.id,
        name=payload.name,
        description=payload.description,
    )
    db.add(group)
    db.commit()
    db.refresh(group)
    return group


@app.put("/api/device-groups/{group_id}", response_model=DeviceGroupResponse)
def update_device_group(
    group_id: int,
    payload: DeviceGroupUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    group = db.query(DeviceGroup).filter(
        DeviceGroup.id == group_id,
        DeviceGroup.user_id == current_user.id,
    ).first()
    if not group:
        raise HTTPException(status_code=404, detail="Device group not found")
    if payload.name is not None:
        group.name = payload.name
    if payload.description is not None:
        group.description = payload.description
    db.commit()
    db.refresh(group)
    return group


@app.delete("/api/device-groups/{group_id}", status_code=204)
def delete_device_group(
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    group = db.query(DeviceGroup).filter(
        DeviceGroup.id == group_id,
        DeviceGroup.user_id == current_user.id,
    ).first()
    if not group:
        raise HTTPException(status_code=404, detail="Device group not found")
    db.delete(group)
    db.commit()


@app.get("/")
def serve_frontend():
    if os.path.exists("frontend/index.html"):
        return FileResponse("frontend/index.html")
    return {"message": "Network AI Orchestrator API", "docs": "/docs"}


# ─────────────────────────────────────────────
# Auth Routes
# ─────────────────────────────────────────────

@app.post("/api/auth/register", response_model=UserResponse, status_code=201)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    logger.info(f"New user registered: {user.email}")
    return user


@app.post("/api/auth/login", response_model=TokenResponse)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    """Standard OAuth2 password flow — username field = email."""
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )
    token = create_access_token(user.id, user.email)
    return {"access_token": token, "token_type": "bearer"}


@app.get("/api/auth/me", response_model=UserResponse)
def me(current_user: User = Depends(get_current_user)):
    return current_user


# ─────────────────────────────────────────────
# Device Routes
# ─────────────────────────────────────────────

@app.get("/api/devices", response_model=List[DeviceResponse])
def list_devices(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return db.query(Device).filter(Device.user_id == current_user.id).all()


@app.post("/api/devices", response_model=DeviceResponse, status_code=201)
def add_device(
    payload: DeviceCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Auto-resolve ned_id from device_type if not explicitly provided
    ned_id = payload.ned_id or ned_id_from_netmiko_type(payload.device_type)

    # If using an authgroup, resolve authgroup_id and store a placeholder password
    ag_id = None
    stored_password = payload.password
    stored_username = payload.username
    if payload.authgroup and payload.authgroup not in ("", "__authgroup__"):
        ag = db.query(Authgroup).filter(
            Authgroup.user_id == current_user.id,
            Authgroup.name == payload.authgroup,
        ).first()
        if ag:
            ag_id = ag.id
            # Always use authgroup's username; device.username is just a display fallback
            stored_username = ag.default_username
            stored_password = "__authgroup__"

    device = Device(
        user_id=current_user.id,
        name=payload.name,
        host=payload.host,
        port=payload.port,
        username=stored_username,
        encrypted_password=encrypt_password(stored_password or "__authgroup__"),
        device_type=payload.device_type,
        ned_id=ned_id,
        authgroup=payload.authgroup or "default",
        authgroup_id=ag_id,
        sync_state="unknown",
        site=payload.site,
        group_id=payload.group_id,
    )
    db.add(device)
    db.commit()
    db.refresh(device)
    logger.info(f"Device added: {device.name} ({device.host}) by user {current_user.email}")
    return device


@app.get("/api/devices/{device_id}", response_model=DeviceResponse)
def get_device(
    device_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    device = _get_owned_device(device_id, current_user.id, db)
    return device


@app.put("/api/devices/{device_id}", response_model=DeviceResponse)
def update_device(
    device_id: int,
    payload: DeviceUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    device = _get_owned_device(device_id, current_user.id, db)

    if payload.name is not None:
        device.name = payload.name
    if payload.host is not None:
        device.host = payload.host
    if payload.port is not None:
        device.port = payload.port
    if payload.device_type is not None:
        device.device_type = payload.device_type
        # Re-resolve ned_id when device_type changes
        if payload.ned_id is None:
            device.ned_id = ned_id_from_netmiko_type(payload.device_type) or device.ned_id
    if payload.ned_id is not None:
        device.ned_id = payload.ned_id
    if payload.authgroup is not None:
        device.authgroup = payload.authgroup
        # Re-wire authgroup_id FK when authgroup name changes
        if payload.authgroup not in ("", "__authgroup__"):
            ag = db.query(Authgroup).filter(
                Authgroup.user_id == current_user.id,
                Authgroup.name == payload.authgroup,
            ).first()
            if ag:
                device.authgroup_id = ag.id
                # Store authgroup's username so display is accurate
                device.username = ag.default_username
                device.encrypted_password = encrypt_password("__authgroup__")
            else:
                device.authgroup_id = None
        else:
            device.authgroup_id = None
            # Switching back to per-device — update credentials if provided
            if payload.username is not None:
                device.username = payload.username
            if payload.password is not None and payload.password not in ("__authgroup__", ""):
                device.encrypted_password = encrypt_password(payload.password)
    else:
        # No authgroup change — update per-device credentials if provided
        if payload.username is not None:
            device.username = payload.username
        if payload.password is not None and payload.password not in ("__authgroup__", ""):
            device.encrypted_password = encrypt_password(payload.password)
        else:
            device.authgroup_id = None
    if payload.site is not None:
        device.site = payload.site
    if payload.group_id is not None:
        device.group_id = payload.group_id

    db.commit()
    db.refresh(device)
    return device


@app.delete("/api/devices/{device_id}", status_code=204)
def delete_device(
    device_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    device = _get_owned_device(device_id, current_user.id, db)
    db.delete(device)
    db.commit()


@app.post("/api/devices/{device_id}/test")
def test_device(
    device_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Test SSH connectivity and credential validity."""
    device = _get_owned_device(device_id, current_user.id, db)
    username, plain_password = _resolve_device_credentials(device, db)

    result = device_connector.test_connectivity(
        host=device.host,
        username=username,
        password=plain_password,
        device_type=device.device_type,
        port=device.port,
    )
    if result["success"]:
        device.last_seen = datetime.utcnow()
        db.commit()
    return result


@app.get("/api/devices/{device_id}/status")
def device_status(
    device_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Pull live status commands from device."""
    device = _get_owned_device(device_id, current_user.id, db)
    username, plain_password = _resolve_device_credentials(device, db)

    result = device_connector.pull_device_data(
        host=device.host,
        username=username,
        password=plain_password,
        device_type=device.device_type,
        port=device.port,
        analysis_type="status",
    )
    if result["success"]:
        device.last_seen = datetime.utcnow()
        db.commit()
    return result


# ─────────────────────────────────────────────
# AI Analysis Routes
# ─────────────────────────────────────────────

@app.post("/api/analysis", response_model=AnalysisResponse, status_code=201)
def run_analysis(
    payload: AnalysisRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Run an AI analysis. If device_id is provided, pulls live data first.
    Falls back to custom_input if no device_id.
    """
    valid_types = {"config_backup"}
    if payload.analysis_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"analysis_type must be one of: {valid_types}")

    device_data = ""
    device_id = payload.device_id

    # Pull live data if a device is specified
    if device_id:
        device = _get_owned_device(device_id, current_user.id, db)
        username, plain_password = _resolve_device_credentials(device, db)

        pull_result = device_connector.pull_device_data(
            host=device.host,
            username=username,
            password=plain_password,
            device_type=device.device_type,
            port=device.port,
            analysis_type=payload.analysis_type,
        )
        if pull_result["success"]:
            device_data = pull_result["data"]
            device.last_seen = datetime.utcnow()
            db.commit()
        else:
            raise HTTPException(
                status_code=502,
                detail=f"Could not connect to device: {pull_result['error']}",
            )

    # Send to Claude
    try:
        result_text = api_client.analyze(
            analysis_type=payload.analysis_type,
            device_data=device_data,
            custom_input=payload.custom_input or "",
        )
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))

    # Save result
    analysis = AnalysisResult(
        user_id=current_user.id,
        device_id=device_id,
        analysis_type=payload.analysis_type,
        prompt=payload.custom_input or f"Live pull from device {device_id}",
        result=result_text,
    )
    db.add(analysis)
    db.commit()
    db.refresh(analysis)

    return analysis


@app.get("/api/analysis/history", response_model=List[AnalysisResponse])
def analysis_history(
    limit: int = 20,
    analysis_type: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(AnalysisResult).filter(AnalysisResult.user_id == current_user.id)
    if analysis_type:
        query = query.filter(AnalysisResult.analysis_type == analysis_type)
    return query.order_by(AnalysisResult.created_at.desc()).limit(limit).all()


# ─────────────────────────────────────────────
# NSO Sync Routes
# ─────────────────────────────────────────────

def _fetch_running_config(device: Device, db: Session) -> str:
    """SSH into device and return running config string."""
    username, plain_password = _resolve_device_credentials(device, db)
    result = device_connector.pull_device_data(
        host=device.host,
        username=username,
        password=plain_password,
        device_type=device.device_type,
        port=device.port,
        analysis_type="config_backup",
    )
    if not result["success"]:
        raise HTTPException(status_code=502, detail=result["error"])
    config = result["data"]
    if config.startswith("### "):
        config = "\n".join(config.split("\n")[1:]).strip()
    return config


@app.post("/api/devices/{device_id}/fetch-config", response_model=ConfigSnapshotResponse, status_code=201)
def fetch_config(
    device_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Download running config from device and store as a new snapshot."""
    device = _get_owned_device(device_id, current_user.id, db)
    config = _fetch_running_config(device, db)

    snap = ConfigSnapshot(device_id=device_id, config=config)
    db.add(snap)
    device.last_seen = datetime.utcnow()
    db.add(SyncHistory(device_id=device_id, action="fetch-config", status="synced",
                       detail=f"Saved {len(config):,} bytes"))
    db.commit()
    db.refresh(snap)
    logger.info(f"Config fetched for device {device_id} ({len(config)} bytes)")
    return snap


@app.get("/api/devices/{device_id}/config", response_model=ConfigSnapshotResponse)
def get_config(
    device_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return the latest stored config snapshot for a device."""
    _get_owned_device(device_id, current_user.id, db)
    snap = (
        db.query(ConfigSnapshot)
        .filter(ConfigSnapshot.device_id == device_id)
        .order_by(ConfigSnapshot.fetched_at.desc())
        .first()
    )
    if not snap:
        raise HTTPException(status_code=404, detail="No config snapshot — run Fetch Config first")
    return snap


@app.post("/api/devices/{device_id}/check-sync", response_model=CheckSyncResponse)
def check_sync(
    device_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Compare latest stored snapshot against live device config."""
    device = _get_owned_device(device_id, current_user.id, db)
    snap = (
        db.query(ConfigSnapshot)
        .filter(ConfigSnapshot.device_id == device_id)
        .order_by(ConfigSnapshot.fetched_at.desc())
        .first()
    )
    if not snap:
        return CheckSyncResponse(status="no-snapshot", diff="",
                                 message="No stored snapshot — run Fetch Config first")

    try:
        live_config = _fetch_running_config(device, db)
    except HTTPException as exc:
        db.add(SyncHistory(device_id=device_id, action="check-sync", status="error",
                           detail=str(exc.detail)))
        db.commit()
        raise

    def _norm(c):
        return [l.rstrip() + "\n" for l in c.splitlines() if l.strip()]

    diff_lines = list(difflib.unified_diff(
        _norm(snap.config), _norm(live_config),
        fromfile=f"stored ({snap.fetched_at.strftime('%Y-%m-%d %H:%M')})",
        tofile="live", lineterm="",
    ))
    diff_text = "\n".join(diff_lines)
    status = "out-of-sync" if diff_text else "in-sync"
    message = "Configuration differs from stored snapshot" if diff_text else "Device is in sync"

    db.add(SyncHistory(device_id=device_id, action="check-sync", status=status,
                       detail=diff_text[:2000]))
    device.last_seen = datetime.utcnow()
    db.commit()
    return CheckSyncResponse(status=status, diff=diff_text, message=message)


@app.post("/api/devices/{device_id}/sync", response_model=ConfigSnapshotResponse)
def sync_device(
    device_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Fetch live config and update the stored snapshot."""
    device = _get_owned_device(device_id, current_user.id, db)
    config = _fetch_running_config(device, db)

    snap = ConfigSnapshot(device_id=device_id, config=config)
    db.add(snap)
    device.last_seen = datetime.utcnow()
    db.add(SyncHistory(device_id=device_id, action="sync", status="synced",
                       detail=f"Snapshot updated ({len(config):,} bytes)"))
    db.commit()
    db.refresh(snap)
    return snap


@app.get("/api/devices/{device_id}/snapshots", response_model=List[ConfigSnapshotResponse])
def list_snapshots(
    device_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all stored config snapshots for a device, newest first."""
    _get_owned_device(device_id, current_user.id, db)
    return (
        db.query(ConfigSnapshot)
        .filter(ConfigSnapshot.device_id == device_id)
        .order_by(ConfigSnapshot.fetched_at.desc())
        .all()
    )


@app.post("/api/devices/{device_id}/restore/{snapshot_id}", response_model=ApplyConfigResponse)
def restore_snapshot(
    device_id: int,
    snapshot_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Restore a stored config snapshot back to the device.
    Diffs the snapshot against the current live config and applies the delta.
    """
    device = _get_owned_device(device_id, current_user.id, db)
    snap = db.query(ConfigSnapshot).filter(
        ConfigSnapshot.id == snapshot_id,
        ConfigSnapshot.device_id == device_id,
    ).first()
    if not snap:
        raise HTTPException(status_code=404, detail="Snapshot not found")

    username, plain_password = _resolve_device_credentials(device, db)

    # Diff snapshot against live config to get minimal restore commands
    try:
        live_config = _fetch_running_config(device, db)
    except HTTPException as exc:
        raise

    delta_commands = generate_delta(live_config, snap.config)
    if not delta_commands:
        return ApplyConfigResponse(
            status="no-change", lines_sent=0, output="",
            message="Device already matches this snapshot",
        )

    # Acquire exclusive device lock
    txn_id = _acquire_lock(device_id, current_user.id, db)
    try:
        result = device_connector.apply_config_set(
            host=device.host,
            username=username,
            password=plain_password,
            config_lines=delta_commands,
            device_type=device.device_type,
            port=device.port,
        )

        if result["success"]:
            # Save a new snapshot reflecting the restored state
            new_snap = ConfigSnapshot(device_id=device_id, config=snap.config)
            db.add(new_snap)
            device.last_seen = datetime.utcnow()
            summary = summarise_delta(delta_commands)
            db.add(SyncHistory(
                device_id=device_id, action="restore",
                status="applied",
                transaction_id=txn_id,
                detail=f"Restored snapshot #{snapshot_id} from {snap.fetched_at.strftime('%Y-%m-%d %H:%M')} — delta: {summary['total']} commands",
            ))
            db.commit()
            return ApplyConfigResponse(
                status="applied",
                lines_sent=result["lines_sent"],
                output=result["output"],
                message=f"Restored snapshot from {snap.fetched_at.strftime('%Y-%m-%d %H:%M UTC')}",
                transaction_id=txn_id,
            )
        else:
            db.add(SyncHistory(device_id=device_id, action="restore", status="error",
                               transaction_id=txn_id, detail=result["error"] or ""))
            db.commit()
            raise HTTPException(status_code=502, detail=result["error"])
    finally:
        _release_lock(device_id, txn_id, db)


@app.post("/api/devices/{device_id}/preview-config")
def preview_config(
    device_id: int,
    payload: ApplyConfigRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Connect to device, fetch its current interface list, resolve any abbreviated
    names in the submitted config to exact canonical names, then return the delta
    commands that WOULD be sent — without applying anything.
    """
    device = _get_owned_device(device_id, current_user.id, db)
    username, plain_password = _resolve_device_credentials(device, db)

    # Step 1 — connect to device and get real interface names
    driver = get_driver(device.device_type)
    iface_result = device_connector.pull_device_data(
        host=device.host,
        username=username,
        password=plain_password,
        device_type=device.device_type,
        port=device.port,
        analysis_type="_interfaces",   # handled below via direct command
    )

    # Pull interface list directly
    device_interfaces = []
    try:
        from netmiko import ConnectHandler
        params = driver.get_connection_params(device.host, username, plain_password, device.port)
        with ConnectHandler(**params) as conn:
            raw = conn.send_command(driver.interfaces_command(), read_timeout=15)
            device_interfaces = driver.parse_interface_names(raw)
    except Exception as e:
        logger.warning(f"Could not fetch interface list from {device.host}: {e}")

    # Step 2 — resolve abbreviated names in submitted config against real device names
    resolved_config = resolve_config(payload.config, device_interfaces)

    # Step 3 — diff against stored snapshot using resolved config
    snap = (
        db.query(ConfigSnapshot)
        .filter(ConfigSnapshot.device_id == device_id)
        .order_by(ConfigSnapshot.fetched_at.desc())
        .first()
    )
    old_config = snap.config if snap else ""
    commands = generate_delta(old_config, resolved_config)
    summary = summarise_delta(commands)
    return {
        "commands": commands,
        "summary": summary,
        "has_changes": len(commands) > 0,
        "resolved_config": resolved_config,   # sent back so apply uses canonical names
        "device_interfaces": device_interfaces,
    }


@app.post("/api/devices/{device_id}/apply-config", response_model=ApplyConfigResponse)
def apply_config(
    device_id: int,
    payload: ApplyConfigRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Apply edited config to the device via SSH.

    Uses generate_delta() to diff the submitted config against the latest
    stored snapshot and produces the minimal IOS command list including
    'no <block>' for removed sections. Pushes only the delta commands.
    After a successful apply, saves the new config as a snapshot.

    Acquires a device lock before pushing; returns 409 if another engineer
    is already pushing to this device.
    """
    device = _get_owned_device(device_id, current_user.id, db)
    username, plain_password = _resolve_device_credentials(device, db)

    # Get stored snapshot as the baseline for diffing
    snap = (
        db.query(ConfigSnapshot)
        .filter(ConfigSnapshot.device_id == device_id)
        .order_by(ConfigSnapshot.fetched_at.desc())
        .first()
    )
    old_config = snap.config if snap else ""

    # Compute minimal delta — includes 'no' commands for removed blocks
    delta_commands = generate_delta(old_config, payload.config)

    if not delta_commands:
        return ApplyConfigResponse(
            status="no-change",
            lines_sent=0,
            output="",
            message="No changes detected between stored snapshot and submitted config",
        )

    # Acquire exclusive device lock
    txn_id = _acquire_lock(device_id, current_user.id, db)
    try:
        result = device_connector.apply_config_set(
            host=device.host,
            username=username,
            password=plain_password,
            config_lines=delta_commands,
            device_type=device.device_type,
            port=device.port,
        )

        if result["success"]:
            # Pull the live config from the device after applying so the snapshot
            # matches exactly what the device has (IOS-XE adds auto-generated lines
            # like 'no shutdown' that differ from what was submitted).
            try:
                live_config = _fetch_running_config(device, db)
            except Exception:
                live_config = payload.config  # fallback to submitted config

            new_snap = ConfigSnapshot(device_id=device_id, config=live_config)
            db.add(new_snap)
            device.last_seen = datetime.utcnow()
            summary = summarise_delta(delta_commands)
            db.add(SyncHistory(
                device_id=device_id, action="apply-config", status="applied",
                transaction_id=txn_id,
                detail=f"Delta: +{summary['added']} -{summary['removed']} ({summary['total']} total commands)",
            ))
            db.commit()
            return ApplyConfigResponse(
                status="applied",
                lines_sent=result["lines_sent"],
                output=result["output"],
                message=f"Applied delta: +{summary['added']} added, -{summary['removed']} removed",
                transaction_id=txn_id,
            )
        else:
            db.add(SyncHistory(device_id=device_id, action="apply-config", status="error",
                               transaction_id=txn_id, detail=result["error"] or ""))
            db.commit()
            raise HTTPException(status_code=502, detail=result["error"])
    finally:
        _release_lock(device_id, txn_id, db)


@app.get("/api/devices/{device_id}/lock")
def get_device_lock(
    device_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return current lock status for a device, or null if unlocked."""
    _get_owned_device(device_id, current_user.id, db)
    now = datetime.utcnow()
    lock = db.query(DeviceLock).filter(
        DeviceLock.device_id == device_id,
        DeviceLock.expires_at > now,
    ).first()
    if not lock:
        return {"locked": False}
    owner = db.query(User).filter(User.id == lock.user_id).first()
    return {
        "locked": True,
        "locked_by": owner.email if owner else "unknown",
        "transaction_id": lock.transaction_id,
        "locked_at": lock.locked_at.isoformat(),
        "expires_at": lock.expires_at.isoformat(),
        "mine": lock.user_id == current_user.id,
    }


@app.delete("/api/devices/{device_id}/lock", status_code=204)
def release_device_lock(
    device_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Release YOUR own lock on a device.
    Engineers cannot force-release another engineer's lock.
    """
    _get_owned_device(device_id, current_user.id, db)
    lock = db.query(DeviceLock).filter(DeviceLock.device_id == device_id).first()
    if not lock:
        raise HTTPException(status_code=404, detail="No active lock on this device")
    if lock.user_id != current_user.id:
        owner = db.query(User).filter(User.id == lock.user_id).first()
        raise HTTPException(
            status_code=403,
            detail=f"Lock is held by {owner.email if owner else 'another engineer'} — you cannot release it",
        )
    db.delete(lock)
    db.commit()
    logger.info(f"Lock manually released on device {device_id} by {current_user.email}")


@app.get("/api/devices/{device_id}/sync-history", response_model=List[SyncHistoryResponse])
def get_sync_history(
    device_id: int,
    limit: int = 20,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return sync/check-sync history for a device."""
    _get_owned_device(device_id, current_user.id, db)
    return (
        db.query(SyncHistory)
        .filter(SyncHistory.device_id == device_id)
        .order_by(SyncHistory.timestamp.desc())
        .limit(limit)
        .all()
    )


# ─────────────────────────────────────────────
# NED-aware Device Actions  (NSO-inspired)
# ─────────────────────────────────────────────

@app.post("/api/devices/{device_id}/sync-from")
def sync_from(
    device_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    NSO sync-from: pull the current running config from the device and
    update the orchestrator's stored copy.  Marks sync_state = 'in-sync'.

    This is the authoritative 'device wins' operation — use it when the device
    is correct and the orchestrator needs to catch up.
    """
    device = _get_owned_device(device_id, current_user.id, db)
    config = _fetch_running_config(device, db)

    snap = ConfigSnapshot(device_id=device_id, config=config)
    db.add(snap)
    device.last_seen = datetime.utcnow()
    device.sync_state = "in-sync"

    # Detect and store platform info from version output
    username, plain_password = _resolve_device_credentials(device, db)
    try:
        driver = get_driver(device.ned_id or device.device_type)
        test_result = device_connector.test_connectivity(
            host=device.host, username=username,
            password=plain_password, device_type=device.device_type, port=device.port,
        )
        if test_result["success"] and not device.platform:
            device.platform = test_result["message"]
    except Exception:
        pass

    db.add(SyncHistory(
        device_id=device_id, action="sync-from", status="synced",
        detail=f"sync-from: pulled {len(config):,} bytes from device",
    ))
    db.commit()
    db.refresh(snap)
    logger.info(f"sync-from completed for device {device.name} ({len(config):,} bytes)")
    return {
        "status": "synced",
        "bytes": len(config),
        "sync_state": "in-sync",
        "snapshot_id": snap.id,
        "message": f"Pulled {len(config):,} bytes from {device.name}",
    }


@app.post("/api/devices/{device_id}/sync-to")
def sync_to(
    device_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    NSO sync-to: push the orchestrator's stored config to the device.
    This is the authoritative 'orchestrator wins' operation — use it when
    the orchestrator has the correct config and the device has drifted.

    Computes the minimal delta between the stored snapshot and the live device,
    then pushes only the changed lines.
    """
    device = _get_owned_device(device_id, current_user.id, db)
    snap = (
        db.query(ConfigSnapshot)
        .filter(ConfigSnapshot.device_id == device_id)
        .order_by(ConfigSnapshot.fetched_at.desc())
        .first()
    )
    if not snap:
        raise HTTPException(status_code=404, detail="No stored config — run sync-from first")

    username, plain_password = _resolve_device_credentials(device, db)

    # Get live config to compute delta
    try:
        live_config = _fetch_running_config(device, db)
    except HTTPException:
        raise

    delta = generate_delta(live_config, snap.config)
    if not delta:
        device.sync_state = "in-sync"
        db.commit()
        return {"status": "in-sync", "lines_sent": 0, "message": "Device already matches stored config"}

    txn_id = _acquire_lock(device_id, current_user.id, db)
    try:
        result = device_connector.apply_config_set(
            host=device.host, username=username, password=plain_password,
            config_lines=delta, device_type=device.device_type, port=device.port,
        )
        summary = summarise_delta(delta)
        if result["success"]:
            device.sync_state = "in-sync"
            device.last_seen = datetime.utcnow()
            db.add(SyncHistory(
                device_id=device_id, action="sync-to", status="applied",
                transaction_id=txn_id,
                detail=f"sync-to: +{summary['added']} -{summary['removed']} ({summary['total']} commands)",
            ))
            db.commit()
            return {
                "status": "applied",
                "lines_sent": result["lines_sent"],
                "sync_state": "in-sync",
                "transaction_id": txn_id,
                "message": f"sync-to: pushed delta +{summary['added']} -{summary['removed']}",
            }
        else:
            device.sync_state = "out-of-sync"
            db.add(SyncHistory(
                device_id=device_id, action="sync-to", status="error",
                transaction_id=txn_id, detail=result["error"] or "",
            ))
            db.commit()
            raise HTTPException(status_code=502, detail=result["error"])
    finally:
        _release_lock(device_id, txn_id, db)


@app.post("/api/devices/{device_id}/compare-config")
def compare_config(
    device_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    NSO compare-config: show a unified diff between the orchestrator's stored
    config and the live device config.

    Returns line-level diff with +/- markers, a summary count, and the
    new sync_state ('in-sync' or 'out-of-sync').  Does NOT push any changes.
    """
    device = _get_owned_device(device_id, current_user.id, db)
    snap = (
        db.query(ConfigSnapshot)
        .filter(ConfigSnapshot.device_id == device_id)
        .order_by(ConfigSnapshot.fetched_at.desc())
        .first()
    )
    if not snap:
        return {
            "sync_state": "unknown",
            "diff": "",
            "added_lines": 0,
            "removed_lines": 0,
            "message": "No stored config — run sync-from first",
        }

    try:
        live_config = _fetch_running_config(device, db)
    except HTTPException as exc:
        db.add(SyncHistory(device_id=device_id, action="compare-config", status="error",
                           detail=str(exc.detail)))
        db.commit()
        raise

    def _norm(c):
        return [l.rstrip() + "\n" for l in c.splitlines() if l.strip()]

    diff_lines = list(difflib.unified_diff(
        _norm(snap.config), _norm(live_config),
        fromfile=f"orchestrator ({snap.fetched_at.strftime('%Y-%m-%d %H:%M')})",
        tofile=f"device-live ({datetime.utcnow().strftime('%Y-%m-%d %H:%M')})",
        lineterm="",
    ))
    diff_text = "\n".join(diff_lines)
    added   = sum(1 for l in diff_lines if l.startswith("+") and not l.startswith("+++"))
    removed = sum(1 for l in diff_lines if l.startswith("-") and not l.startswith("---"))
    sync_state = "out-of-sync" if diff_text else "in-sync"

    device.sync_state = sync_state
    device.last_seen = datetime.utcnow()
    db.add(SyncHistory(
        device_id=device_id, action="compare-config", status=sync_state,
        detail=diff_text[:2000],
    ))
    db.commit()

    return {
        "sync_state": sync_state,
        "diff": diff_text,
        "added_lines": added,
        "removed_lines": removed,
        "message": (
            f"compare-config: +{added} -{removed} lines differ"
            if diff_text else "Device config matches orchestrator"
        ),
    }


@app.get("/api/devices/{device_id}/live-status/{category}")
def get_live_status(
    device_id: int,
    category: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Pull live operational data from the device for a specific category.
    Categories are NED-defined (e.g. 'bgp', 'routes', 'interfaces', 'arp').
    This data is NOT stored — it's real-time only.
    """
    device = _get_owned_device(device_id, current_user.id, db)
    driver = get_driver(device.ned_id or device.device_type)

    commands = driver.get_live_status_commands(category)
    if not commands:
        available = driver.get_live_status_categories()
        raise HTTPException(
            status_code=404,
            detail=f"Category '{category}' not supported by NED '{driver.NED_ID}'. "
                   f"Available: {available}",
        )

    username, plain_password = _resolve_device_credentials(device, db)
    try:
        from netmiko import ConnectHandler
        params = driver.get_connection_params(device.host, username, plain_password, device.port)
        output_parts = {}
        with ConnectHandler(**params) as conn:
            for cmd in commands:
                output_parts[cmd] = conn.send_command(cmd, read_timeout=30)
        device.last_seen = datetime.utcnow()
        db.commit()
        return {
            "device": device.name,
            "category": category,
            "ned_id": driver.NED_ID,
            "timestamp": datetime.utcnow().isoformat(),
            "data": output_parts,
        }
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Could not pull live-status: {e}")


@app.get("/api/devices/{device_id}/ned-info")
def get_device_ned_info(
    device_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Return NED details for a device: which NED handles it, capabilities,
    available live-status categories, and current sync_state.
    """
    device = _get_owned_device(device_id, current_user.id, db)
    driver = get_driver(device.ned_id or device.device_type)
    ned_meta = get_ned_metadata(driver.NED_ID)

    return {
        "device_name": device.name,
        "ned_id": driver.NED_ID,
        "ned_version": driver.NED_VERSION,
        "protocol": driver.PROTOCOL,
        "capabilities": list(driver.CAPABILITIES),
        "live_status_categories": driver.get_live_status_categories(),
        "sync_state": device.sync_state,
        "platform": device.platform,
        "authgroup": device.authgroup,
        "ned_description": ned_meta.description if ned_meta else "",
    }


# ─────────────────────────────────────────────
# Services
# ─────────────────────────────────────────────

_jinja_env = Environment(undefined=StrictUndefined, trim_blocks=True, lstrip_blocks=True)


def _render_template(template_body: str, variable_values: dict) -> list[str]:
    """Render a Jinja2 service template with variable values → list of CLI commands."""
    try:
        tmpl = _jinja_env.from_string(template_body)
        rendered = tmpl.render(**variable_values)
    except UndefinedError as e:
        raise HTTPException(status_code=422, detail=f"Missing variable: {e}")
    except TemplateSyntaxError as e:
        raise HTTPException(status_code=422, detail=f"Template syntax error: {e}")
    # Return non-empty lines
    return [line for line in rendered.splitlines() if line.strip()]


@app.get("/api/services", response_model=List[ServiceTemplateResponse])
def list_service_templates(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return (
        db.query(ServiceTemplate)
        .filter(ServiceTemplate.user_id == current_user.id)
        .order_by(ServiceTemplate.created_at.desc())
        .all()
    )


@app.post("/api/services", response_model=ServiceTemplateResponse, status_code=201)
def create_service_template(
    payload: ServiceTemplateCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    svc = ServiceTemplate(user_id=current_user.id, **payload.model_dump())
    db.add(svc)
    db.commit()
    db.refresh(svc)
    return svc


@app.get("/api/services/{svc_id}", response_model=ServiceTemplateResponse)
def get_service_template(
    svc_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    svc = db.query(ServiceTemplate).filter(
        ServiceTemplate.id == svc_id,
        ServiceTemplate.user_id == current_user.id,
    ).first()
    if not svc:
        raise HTTPException(status_code=404, detail="Service template not found")
    return svc


@app.put("/api/services/{svc_id}", response_model=ServiceTemplateResponse)
def update_service_template(
    svc_id: int,
    payload: ServiceTemplateUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    svc = db.query(ServiceTemplate).filter(
        ServiceTemplate.id == svc_id,
        ServiceTemplate.user_id == current_user.id,
    ).first()
    if not svc:
        raise HTTPException(status_code=404, detail="Service template not found")
    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(svc, field, value)
    svc.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(svc)
    return svc


@app.delete("/api/services/{svc_id}", status_code=204)
def delete_service_template(
    svc_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    svc = db.query(ServiceTemplate).filter(
        ServiceTemplate.id == svc_id,
        ServiceTemplate.user_id == current_user.id,
    ).first()
    if not svc:
        raise HTTPException(status_code=404, detail="Service template not found")
    db.delete(svc)
    db.commit()


@app.post("/api/services/{svc_id}/preview", response_model=ServicePreviewResponse)
def preview_service(
    svc_id: int,
    payload: ServicePreviewRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Render the template with provided variables and return the CLI preview."""
    svc = db.query(ServiceTemplate).filter(
        ServiceTemplate.id == svc_id,
        ServiceTemplate.user_id == current_user.id,
    ).first()
    if not svc:
        raise HTTPException(status_code=404, detail="Service template not found")
    lines = _render_template(svc.template_body, payload.variable_values)
    return ServicePreviewResponse(rendered="\n".join(lines), lines=lines)


@app.post("/api/services/{svc_id}/dry-run", response_model=ServiceDryRunResponse)
def dry_run_service(
    svc_id: int,
    payload: ServiceDryRunRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Render the template, SSH to the device, pull running config,
    then compare each line — returns per-line status: new | exists.
    """
    svc = db.query(ServiceTemplate).filter(
        ServiceTemplate.id == svc_id,
        ServiceTemplate.user_id == current_user.id,
    ).first()
    if not svc:
        raise HTTPException(status_code=404, detail="Service template not found")

    device = _get_owned_device(payload.device_id, current_user.id, db)

    # 1. Render template → CLI lines
    rendered_lines = _render_template(svc.template_body, payload.variable_values)

    # 2. Pull running config from device
    username, plain_password = _resolve_device_credentials(device, db)
    pull = device_connector.pull_device_data(
        host=device.host,
        username=username,
        password=plain_password,
        device_type=device.device_type,
        port=device.port,
        analysis_type="config_backup",
    )
    if not pull["success"]:
        raise HTTPException(status_code=502, detail=f"Cannot reach device: {pull['error']}")

    running_config = pull["data"]
    # Strip header added by pull_device_data
    if running_config.startswith("### "):
        running_config = "\n".join(running_config.split("\n")[1:]).strip()

    # 3. Build a flat set of stripped running-config lines for fast lookup
    running_lines_set = {
        l.strip() for l in running_config.splitlines()
        if l.strip() and not l.strip().startswith("!")
    }

    # 4. Classify each rendered line
    result_lines: list[DryRunLine] = []
    new_count = 0
    exists_count = 0

    for raw in rendered_lines:
        indent = len(raw) - len(raw.lstrip())
        stripped = raw.strip()

        # Determine if this line already exists in the running config
        if stripped in running_lines_set:
            status = "exists"
            exists_count += 1
        else:
            status = "new"
            new_count += 1

        result_lines.append(DryRunLine(line=raw, indent=indent, status=status))

    return ServiceDryRunResponse(
        lines=result_lines,
        new_count=new_count,
        exists_count=exists_count,
        device_name=device.name,
    )


@app.post("/api/services/{svc_id}/deploy", response_model=ServiceDeployResponse)
def deploy_service(
    svc_id: int,
    payload: ServiceDeployRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Render template and push commands to the target device."""
    svc = db.query(ServiceTemplate).filter(
        ServiceTemplate.id == svc_id,
        ServiceTemplate.user_id == current_user.id,
    ).first()
    if not svc:
        raise HTTPException(status_code=404, detail="Service template not found")

    device = _get_owned_device(payload.device_id, current_user.id, db)
    lines = _render_template(svc.template_body, payload.variable_values)

    username, plain_password = _resolve_device_credentials(device, db)

    # Acquire exclusive device lock
    txn_id = _acquire_lock(payload.device_id, current_user.id, db)
    try:
        result = device_connector.apply_config_set(
            host=device.host,
            username=username,
            password=plain_password,
            config_lines=lines,
            device_type=device.device_type,
            port=device.port,
        )

        inst = ServiceInstance(
            template_id=svc_id,
            device_id=payload.device_id,
            user_id=current_user.id,
            variable_values=json.dumps(payload.variable_values),
            status="deployed" if result["success"] else "error",
            output=result.get("output", "") or result.get("error", ""),
        )
        db.add(inst)
        device.last_seen = datetime.utcnow()
        db.commit()
        db.refresh(inst)

        if not result["success"]:
            raise HTTPException(status_code=502, detail=result.get("error", "Deploy failed"))

        # ── Auto-snapshot: pull running config immediately after deploy ──
        # This keeps the stored baseline in sync with what the tool just pushed,
        # so check-sync only flags changes made directly on the router.
        try:
            new_config = _fetch_running_config(device, db)
            snap = ConfigSnapshot(device_id=payload.device_id, config=new_config)
            db.add(snap)
            db.add(SyncHistory(
                device_id=payload.device_id,
                action="sync",
                status="synced",
                transaction_id=txn_id,
                detail=f"Auto-snapshot after service deploy '{svc.name}' ({len(new_config):,} bytes)",
            ))
            db.commit()
            logger.info(f"Auto-snapshot saved for device {device.name} after service deploy")
        except Exception as e:
            logger.warning(f"Auto-snapshot failed after deploy (device {device.name}): {e}")
            # Non-fatal — deploy already succeeded

        return ServiceDeployResponse(
            status="deployed",
            lines_sent=result["lines_sent"],
            output=result["output"],
            message=f"Service '{svc.name}' deployed — {len(lines)} commands sent",
            instance_id=inst.id,
            transaction_id=txn_id,
        )
    finally:
        _release_lock(payload.device_id, txn_id, db)


# ─────────────────────────────────────────────
# Device Lock helpers
# ─────────────────────────────────────────────

LOCK_TIMEOUT_MINUTES = 10  # auto-expire stale locks


def _acquire_lock(device_id: int, user_id: int, db: Session) -> str:
    """
    Acquire an exclusive write lock on a device.
    Returns a new transaction_id on success.
    Raises HTTP 409 if the device is already locked by another session.
    Expired locks are cleaned up automatically.
    """
    now = datetime.utcnow()

    # Remove stale locks first
    db.query(DeviceLock).filter(DeviceLock.expires_at < now).delete(synchronize_session=False)
    db.commit()

    existing = db.query(DeviceLock).filter(DeviceLock.device_id == device_id).first()
    if existing:
        owner = db.query(User).filter(User.id == existing.user_id).first()
        raise HTTPException(
            status_code=409,
            detail={
                "error": "Device is locked by another engineer",
                "locked_by": owner.email if owner else "unknown",
                "transaction_id": existing.transaction_id,
                "locked_at": existing.locked_at.isoformat(),
                "expires_at": existing.expires_at.isoformat(),
            },
        )

    txn_id = str(uuid.uuid4())
    lock = DeviceLock(
        device_id=device_id,
        user_id=user_id,
        transaction_id=txn_id,
        expires_at=now + timedelta(minutes=LOCK_TIMEOUT_MINUTES),
    )
    db.add(lock)
    db.commit()
    logger.info(f"Lock acquired on device {device_id} — txn={txn_id}")
    return txn_id


def _release_lock(device_id: int, transaction_id: str, db: Session) -> None:
    """Release a device lock by transaction_id."""
    db.query(DeviceLock).filter(
        DeviceLock.device_id == device_id,
        DeviceLock.transaction_id == transaction_id,
    ).delete(synchronize_session=False)
    db.commit()
    logger.info(f"Lock released on device {device_id} — txn={transaction_id}")


# ─────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────

def _get_owned_device(device_id: int, user_id: int, db: Session) -> Device:
    device = db.query(Device).filter(
        Device.id == device_id,
        Device.user_id == user_id,
    ).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


def _resolve_device_credentials(device: Device, db: Session) -> tuple[str, str]:
    """
    Return (username, plaintext_password) for a device.

    Resolution order (mirrors NSO authgroup behaviour):
      1. If the device has an authgroup_id → fetch credentials from that Authgroup row.
      2. If the device has an authgroup name (string) → look up by name for this user.
      3. Fall back to the device's own username / encrypted_password fields.

    The password stored on Authgroup rows is also encrypted with Fernet (same key)
    so it is decrypted the same way as device passwords.
    """
    # 1. Prefer authgroup_id FK
    if device.authgroup_id:
        ag = db.query(Authgroup).filter(Authgroup.id == device.authgroup_id).first()
        if ag:
            return ag.default_username, decrypt_password(ag.encrypted_password)

    # 2. Fall back to authgroup name lookup
    if device.authgroup and device.authgroup not in ("", "default", "__authgroup__"):
        ag = db.query(Authgroup).filter(
            Authgroup.user_id == device.user_id,
            Authgroup.name == device.authgroup,
        ).first()
        if ag:
            return ag.default_username, decrypt_password(ag.encrypted_password)
        # Authgroup explicitly named but not found — raise rather than silently
        # falling back to stale per-device credentials
        raise HTTPException(
            status_code=502,
            detail=f"Authgroup '{device.authgroup}' not found — update the device to fix credentials.",
        )

    # 3. Per-device credentials (authgroup is null, empty, or "default" with no matching row)
    return device.username, decrypt_password(device.encrypted_password)
