from dataclasses import dataclass


@dataclass
class FirewallInterface:
    device: str
    context: str
    interface: str
    nameif: str = None
    security_level: int = None
    ip: str = None
    mask: str = None
    standby_ip: str = None
    vlan: int = None
    description: str = None