from dataclasses import dataclass


@dataclass
class FirewallInterface:
    device: str
    interface: str

    nameif: str | None = None
    vlan: int | None = None
    ip: str | None = None
    mask: str | None = None
    description: str | None = None
    security_level: int | None = None