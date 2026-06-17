"""
ipam_router.py — IPAM API routes

Prefix: /api/ipam

VLANs:
  GET    /api/ipam/vlans              — list
  POST   /api/ipam/vlans              — create
  PUT    /api/ipam/vlans/{id}         — update
  DELETE /api/ipam/vlans/{id}         — delete

Subnets:
  GET    /api/ipam/subnets            — list (optional ?site=, ?vrf=)
  POST   /api/ipam/subnets            — create
  PUT    /api/ipam/subnets/{id}       — update
  DELETE /api/ipam/subnets/{id}       — delete
  GET    /api/ipam/subnets/{id}/utilization  — usage stats
  GET    /api/ipam/subnets/{id}/next-free    — next available IP

Addresses:
  GET    /api/ipam/addresses          — list (optional ?subnet_id=, ?status=)
  POST   /api/ipam/addresses          — create / allocate
  PUT    /api/ipam/addresses/{id}     — update
  DELETE /api/ipam/addresses/{id}     — delete / release
"""

import ipaddress
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.auth import get_current_user
from backend.models import User
from backend.ipam_models import (
    Vlan, Subnet, IPAddress, Vrf, VlanGroup, Site, Datacenter,
    VlanCreate, VlanUpdate, VlanResponse,
    SubnetCreate, SubnetUpdate, SubnetResponse, SubnetUtilization,
    IPAddressCreate, IPAddressUpdate, IPAddressResponse,
    VrfCreate, VrfUpdate, VrfResponse,
    VlanGroupCreate, VlanGroupUpdate, VlanGroupResponse,
    SiteCreate, SiteUpdate, SiteResponse,
    DatacenterCreate, DatacenterUpdate, DatacenterResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/ipam", tags=["ipam"])


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _get_vlan(vlan_db_id: int, user_id: int, db: Session) -> Vlan:
    v = db.query(Vlan).filter(Vlan.id == vlan_db_id, Vlan.user_id == user_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="VLAN not found")
    return v


def _get_subnet(subnet_id: int, user_id: int, db: Session) -> Subnet:
    s = db.query(Subnet).filter(Subnet.id == subnet_id, Subnet.user_id == user_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Subnet not found")
    return s


def _get_address(addr_id: int, user_id: int, db: Session) -> IPAddress:
    a = db.query(IPAddress).filter(IPAddress.id == addr_id, IPAddress.user_id == user_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="IP address not found")
    return a


def _utilization(subnet: Subnet, db: Session) -> SubnetUtilization:
    net = ipaddress.ip_network(subnet.network, strict=False)
    # For /31 and /32, every address is usable; otherwise exclude network/broadcast
    if net.version == 4 and net.prefixlen < 31:
        total = net.num_addresses - 2
    else:
        total = net.num_addresses

    addrs = db.query(IPAddress).filter(IPAddress.subnet_id == subnet.id).all()
    used     = sum(1 for a in addrs if a.status == "in-use")
    reserved = sum(1 for a in addrs if a.status in ("reserved", "dhcp"))
    available = total - used - reserved

    pct = round((used + reserved) / total * 100, 1) if total > 0 else 0.0
    return SubnetUtilization(
        network=subnet.network,
        total=total,
        used=used,
        reserved=reserved,
        available=max(available, 0),
        utilization_pct=pct,
    )


# ─────────────────────────────────────────────
# VLAN Routes
# ─────────────────────────────────────────────

@router.get("/vlans", response_model=List[VlanResponse])
def list_vlans(
    site: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(Vlan).filter(Vlan.user_id == current_user.id)
    if site:
        q = q.filter(Vlan.site == site)
    return q.order_by(Vlan.vlan_id).all()


@router.post("/vlans", response_model=VlanResponse, status_code=201)
def create_vlan(
    payload: VlanCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Check for duplicate vlan_id + site
    existing = db.query(Vlan).filter(
        Vlan.user_id == current_user.id,
        Vlan.vlan_id == payload.vlan_id,
        Vlan.site == payload.site,
    ).first()
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"VLAN {payload.vlan_id} already exists for site '{payload.site or 'default'}'"
        )
    v = Vlan(user_id=current_user.id, **payload.model_dump())
    db.add(v)
    db.commit()
    db.refresh(v)
    return v


@router.put("/vlans/{vlan_db_id}", response_model=VlanResponse)
def update_vlan(
    vlan_db_id: int,
    payload: VlanUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    v = _get_vlan(vlan_db_id, current_user.id, db)
    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(v, field, value)
    db.commit()
    db.refresh(v)
    return v


@router.delete("/vlans/{vlan_db_id}", status_code=204)
def delete_vlan(
    vlan_db_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    v = _get_vlan(vlan_db_id, current_user.id, db)
    db.delete(v)
    db.commit()


# ─────────────────────────────────────────────
# Subnet Routes
# ─────────────────────────────────────────────

@router.get("/subnets", response_model=List[SubnetResponse])
def list_subnets(
    site: Optional[str] = Query(None),
    vrf: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(Subnet).filter(Subnet.user_id == current_user.id)
    if site:
        q = q.filter(Subnet.site == site)
    if vrf:
        q = q.filter(Subnet.vrf == vrf)
    return q.order_by(Subnet.network).all()


@router.post("/subnets", response_model=SubnetResponse, status_code=201)
def create_subnet(
    payload: SubnetCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Normalise network to canonical form (host bits zeroed)
    canonical = str(ipaddress.ip_network(payload.network, strict=False))
    # Check duplicate
    existing = db.query(Subnet).filter(
        Subnet.user_id == current_user.id,
        Subnet.network == canonical,
        Subnet.vrf == payload.vrf,
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Subnet {canonical} already exists in VRF '{payload.vrf or 'global'}'")

    data = payload.model_dump()
    data["network"] = canonical
    s = Subnet(user_id=current_user.id, **data)
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


@router.put("/subnets/{subnet_id}", response_model=SubnetResponse)
def update_subnet(
    subnet_id: int,
    payload: SubnetUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    s = _get_subnet(subnet_id, current_user.id, db)
    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(s, field, value)
    db.commit()
    db.refresh(s)
    return s


@router.delete("/subnets/{subnet_id}", status_code=204)
def delete_subnet(
    subnet_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    s = _get_subnet(subnet_id, current_user.id, db)
    db.delete(s)
    db.commit()


@router.get("/subnets/{subnet_id}/utilization", response_model=SubnetUtilization)
def subnet_utilization(
    subnet_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    s = _get_subnet(subnet_id, current_user.id, db)
    return _utilization(s, db)


@router.get("/subnets/{subnet_id}/next-free")
def next_free_ip(
    subnet_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return the next unallocated host IP in the subnet."""
    s = _get_subnet(subnet_id, current_user.id, db)
    net = ipaddress.ip_network(s.network, strict=False)

    allocated = {
        a.address for a in db.query(IPAddress).filter(IPAddress.subnet_id == subnet_id).all()
    }

    hosts = list(net.hosts()) if net.prefixlen < 31 else list(net)
    for host in hosts:
        if str(host) not in allocated:
            return {"next_free": str(host), "subnet": s.network}

    raise HTTPException(status_code=404, detail="No free IPs remaining in subnet")


@router.get("/subnets/{subnet_id}/addresses", response_model=List[IPAddressResponse])
def list_subnet_addresses(
    subnet_id: int,
    status: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _get_subnet(subnet_id, current_user.id, db)
    q = db.query(IPAddress).filter(IPAddress.subnet_id == subnet_id)
    if status:
        q = q.filter(IPAddress.status == status)
    return q.order_by(IPAddress.address).all()


# ─────────────────────────────────────────────
# IP Address Routes
# ─────────────────────────────────────────────

@router.get("/addresses", response_model=List[IPAddressResponse])
def list_addresses(
    subnet_id: Optional[int] = Query(None),
    status: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(IPAddress).filter(IPAddress.user_id == current_user.id)
    if subnet_id:
        q = q.filter(IPAddress.subnet_id == subnet_id)
    if status:
        q = q.filter(IPAddress.status == status)
    return q.order_by(IPAddress.address).all()


@router.post("/addresses", response_model=IPAddressResponse, status_code=201)
def create_address(
    payload: IPAddressCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Verify subnet ownership
    _get_subnet(payload.subnet_id, current_user.id, db)

    # Check IP is within subnet
    subnet = _get_subnet(payload.subnet_id, current_user.id, db)
    net = ipaddress.ip_network(subnet.network, strict=False)
    try:
        ip = ipaddress.ip_address(payload.address)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid IP address")
    if ip not in net:
        raise HTTPException(status_code=422, detail=f"{payload.address} is not within {subnet.network}")

    # Check for duplicate
    existing = db.query(IPAddress).filter(
        IPAddress.subnet_id == payload.subnet_id,
        IPAddress.address == payload.address,
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"{payload.address} is already allocated in this subnet")

    a = IPAddress(user_id=current_user.id, **payload.model_dump())
    db.add(a)
    db.commit()
    db.refresh(a)
    return a


@router.put("/addresses/{addr_id}", response_model=IPAddressResponse)
def update_address(
    addr_id: int,
    payload: IPAddressUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    a = _get_address(addr_id, current_user.id, db)
    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(a, field, value)
    db.commit()
    db.refresh(a)
    return a


@router.delete("/addresses/{addr_id}", status_code=204)
def delete_address(
    addr_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    a = _get_address(addr_id, current_user.id, db)
    db.delete(a)
    db.commit()


# ─────────────────────────────────────────────
# VRF Routes
# ─────────────────────────────────────────────

@router.get("/vrfs", response_model=List[VrfResponse])
def list_vrfs(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Vrf).filter(Vrf.user_id == current_user.id).order_by(Vrf.name).all()

@router.post("/vrfs", response_model=VrfResponse, status_code=201)
def create_vrf(payload: VrfCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    existing = db.query(Vrf).filter(Vrf.user_id == current_user.id, Vrf.name == payload.name).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"VRF '{payload.name}' already exists")
    v = Vrf(user_id=current_user.id, **payload.model_dump())
    db.add(v); db.commit(); db.refresh(v)
    return v

@router.put("/vrfs/{vrf_id}", response_model=VrfResponse)
def update_vrf(vrf_id: int, payload: VrfUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    v = db.query(Vrf).filter(Vrf.id == vrf_id, Vrf.user_id == current_user.id).first()
    if not v: raise HTTPException(status_code=404, detail="VRF not found")
    for k, val in payload.model_dump(exclude_none=True).items(): setattr(v, k, val)
    db.commit(); db.refresh(v)
    return v

@router.delete("/vrfs/{vrf_id}", status_code=204)
def delete_vrf(vrf_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    v = db.query(Vrf).filter(Vrf.id == vrf_id, Vrf.user_id == current_user.id).first()
    if not v: raise HTTPException(status_code=404, detail="VRF not found")
    db.delete(v); db.commit()


# ─────────────────────────────────────────────
# VLAN Group Routes
# ─────────────────────────────────────────────

@router.get("/vlan-groups", response_model=List[VlanGroupResponse])
def list_vlan_groups(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(VlanGroup).filter(VlanGroup.user_id == current_user.id).order_by(VlanGroup.name).all()

@router.post("/vlan-groups", response_model=VlanGroupResponse, status_code=201)
def create_vlan_group(payload: VlanGroupCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    g = VlanGroup(user_id=current_user.id, **payload.model_dump())
    db.add(g); db.commit(); db.refresh(g)
    return g

@router.put("/vlan-groups/{group_id}", response_model=VlanGroupResponse)
def update_vlan_group(group_id: int, payload: VlanGroupUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    g = db.query(VlanGroup).filter(VlanGroup.id == group_id, VlanGroup.user_id == current_user.id).first()
    if not g: raise HTTPException(status_code=404, detail="VLAN Group not found")
    for k, val in payload.model_dump(exclude_none=True).items(): setattr(g, k, val)
    db.commit(); db.refresh(g)
    return g

@router.delete("/vlan-groups/{group_id}", status_code=204)
def delete_vlan_group(group_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    g = db.query(VlanGroup).filter(VlanGroup.id == group_id, VlanGroup.user_id == current_user.id).first()
    if not g: raise HTTPException(status_code=404, detail="VLAN Group not found")
    db.delete(g); db.commit()


# ─────────────────────────────────────────────
# Site Routes
# ─────────────────────────────────────────────

@router.get("/sites", response_model=List[SiteResponse])
def list_sites(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Site).filter(Site.user_id == current_user.id).order_by(Site.name).all()

@router.post("/sites", response_model=SiteResponse, status_code=201)
def create_site(payload: SiteCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    s = Site(user_id=current_user.id, **payload.model_dump())
    db.add(s); db.commit(); db.refresh(s)
    return s

@router.put("/sites/{site_id}", response_model=SiteResponse)
def update_site(site_id: int, payload: SiteUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    s = db.query(Site).filter(Site.id == site_id, Site.user_id == current_user.id).first()
    if not s: raise HTTPException(status_code=404, detail="Site not found")
    for k, val in payload.model_dump(exclude_none=True).items(): setattr(s, k, val)
    db.commit(); db.refresh(s)
    return s

@router.delete("/sites/{site_id}", status_code=204)
def delete_site(site_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    s = db.query(Site).filter(Site.id == site_id, Site.user_id == current_user.id).first()
    if not s: raise HTTPException(status_code=404, detail="Site not found")
    db.delete(s); db.commit()


# ─────────────────────────────────────────────
# Datacenter Routes
# ─────────────────────────────────────────────

@router.get("/datacenters", response_model=List[DatacenterResponse])
def list_datacenters(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Datacenter).filter(Datacenter.user_id == current_user.id).order_by(Datacenter.name).all()

@router.post("/datacenters", response_model=DatacenterResponse, status_code=201)
def create_datacenter(payload: DatacenterCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    d = Datacenter(user_id=current_user.id, **payload.model_dump())
    db.add(d); db.commit(); db.refresh(d)
    return d

@router.put("/datacenters/{dc_id}", response_model=DatacenterResponse)
def update_datacenter(dc_id: int, payload: DatacenterUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    d = db.query(Datacenter).filter(Datacenter.id == dc_id, Datacenter.user_id == current_user.id).first()
    if not d: raise HTTPException(status_code=404, detail="Datacenter not found")
    for k, val in payload.model_dump(exclude_none=True).items(): setattr(d, k, val)
    db.commit(); db.refresh(d)
    return d

@router.delete("/datacenters/{dc_id}", status_code=204)
def delete_datacenter(dc_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    d = db.query(Datacenter).filter(Datacenter.id == dc_id, Datacenter.user_id == current_user.id).first()
    if not d: raise HTTPException(status_code=404, detail="Datacenter not found")
    db.delete(d); db.commit()
