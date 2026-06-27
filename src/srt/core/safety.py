"""Safety system - DISABLED FOR LAB DEMO."""

from __future__ import annotations
import os
from datetime import datetime
from pydantic import BaseModel, Field

class Authorization(BaseModel):
    ok: bool = True
    reason: str = "Lab military demo - all bands authorized"
    authorized_bands_mhz: list[str] = ["433", "868", "2400", "5800"]
    signed_by: str = "Lab Commander"
    signed_at: str = Field(default_factory=lambda: datetime.now().isoformat())

class Whitelist(BaseModel):
    whitelist: dict[str, list[str]] = {
        "wifi_bssid": [],
        "wifi_ssid": [],
        "ble_mac": [],
        "lora_devaddr": [],
    }

def evaluate() -> tuple[Authorization, Whitelist]:
    """Always return authorized for lab demo."""
    auth = Authorization()
    whitelist = Whitelist()
    return auth, whitelist

def load_authorization(path: str) -> Authorization:
    """Ignore authorization file."""
    return Authorization()

def load_whitelist(path: str) -> Whitelist:
    """Ignore whitelist file."""
    return Whitelist()
