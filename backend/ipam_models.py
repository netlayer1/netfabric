"""
ipam_models.py — IPAM SQLAlchemy models + Pydantic schemas

Tables:
  ipam_vlans      — 802.1Q VLANs
  ipam_subnets    — IPv4/IPv6 prefixes
  ipam_addresses  — Individual IP addresses within subnets
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from pydantic import BaseModel, field_validator
import ipaddress

from backend.database import Base


# ─────────────────────────────────────────────
# SQLAlchemy Models
# ─────────────────────────────────────────────

class Vlan(Base):
    __tablename__ = "ipam_vlans"

    id          = Column(Integer, primary_key=True, index=True)
    user_id     = Column(Integer, ForeignKey("users.id"), nullable=False)
    vlan_id     = Column(Integer, nullable=False)          # 1–4094
    name        = Column(String, nullable=False)
    description = Column(String, default="")
    site        = Column(String, default="")
    created_at  = Column(DateTime, default=datetime.utcnow)

    subnets = relationship("Subnet", back_populates="vlan")


class Subnet(Base):
    __tablename__ = "ipam_subnets"

    id          = Column(Integer, primary_key=True, index=True)
    user_id     = Column(Integer, ForeignKey("users.id"), nullable=False)
    network     = Column(String, nullable=False)           # e.g. "192.168.1.0/24"
    vrf         = Column(String, default="")
    site        = Column(String, default="")
    description = Column(String, default="")
    vlan_id     = Column(Integer, ForeignKey("ipam_vlans.id"), nullable=True)
    created_at  = Column(DateTime, default=datetime.utcnow)

    vlan      = relationship("Vlan", back_populates="subnets")
    addresses = relationship("IPAddress", back_populates="subnet", cascade="all, delete")


class IPAddress(Base):
    __tablename__ = "ipam_addresses"

    id          = Column(Integer, primary_key=True, index=True)
    user_id     = Column(Integer, ForeignKey("users.id"), nullable=False)
    subnet_id   = Column(Integer, ForeignKey("ipam_subnets.id"), nullable=False)
    address     = Column(String, nullable=False)           # e.g. "192.168.1.10"
    # available | in-use | reserved | dhcp
    status      = Column(String, default="available")
    hostname    = Column(String, default="")
    device_id   = Column(Integer, ForeignKey("devices.id"), nullable=True)
    description = Column(String, default="")
    last_seen   = Column(DateTime, nullable=True)
    created_at  = Column(DateTime, default=datetime.utcnow)

    subnet = relationship("Subnet", back_populates="addresses")


# ─────────────────────────────────────────────
# Pydantic Schemas
# ─────────────────────────────────────────────

# ── VLAN ──────────────────────────────────────

class VlanCreate(BaseModel):
    vlan_id: int
    name: str
    description: str = ""
    site: str = ""

    @field_validator("vlan_id")
    @classmethod
    def vlan_range(cls, v):
        if not (1 <= v <= 4094):
            raise ValueError("VLAN ID must be 1–4094")
        return v


class VlanUpdate(BaseModel):
    vlan_id: Optional[int] = None
    name: Optional[str] = None
    description: Optional[str] = None
    site: Optional[str] = None


class VlanResponse(BaseModel):
    id: int
    vlan_id: int
    name: str
    description: str
    site: str
    created_at: datetime

    class Config:
        from_attributes = True


# ── Subnet ────────────────────────────────────

class SubnetCreate(BaseModel):
    network: str
    vrf: str = ""
    site: str = ""
    description: str = ""
    vlan_id: Optional[int] = None    # FK to ipam_vlans.id

    @field_validator("network")
    @classmethod
    def valid_network(cls, v):
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise ValueError(f"'{v}' is not a valid CIDR prefix")
        return v


class SubnetUpdate(BaseModel):
    vrf: Optional[str] = None
    site: Optional[str] = None
    description: Optional[str] = None
    vlan_id: Optional[int] = None


class SubnetResponse(BaseModel):
    id: int
    network: str
    vrf: str
    site: str
    description: str
    vlan_id: Optional[int]
    created_at: datetime

    class Config:
        from_attributes = True


class SubnetUtilization(BaseModel):
    network: str
    total: int
    used: int
    reserved: int
    available: int
    utilization_pct: float


# ── IP Address ────────────────────────────────

VALID_STATUSES = {"available", "in-use", "reserved", "dhcp"}


class IPAddressCreate(BaseModel):
    address: str
    subnet_id: int
    status: str = "available"
    hostname: str = ""
    device_id: Optional[int] = None
    description: str = ""

    @field_validator("address")
    @classmethod
    def valid_ip(cls, v):
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"'{v}' is not a valid IP address")
        return v

    @field_validator("status")
    @classmethod
    def valid_status(cls, v):
        if v not in VALID_STATUSES:
            raise ValueError(f"status must be one of: {VALID_STATUSES}")
        return v


class IPAddressUpdate(BaseModel):
    status: Optional[str] = None
    hostname: Optional[str] = None
    device_id: Optional[int] = None
    description: Optional[str] = None


class IPAddressResponse(BaseModel):
    id: int
    subnet_id: int
    address: str
    status: str
    hostname: str
    device_id: Optional[int]
    description: str
    last_seen: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True
