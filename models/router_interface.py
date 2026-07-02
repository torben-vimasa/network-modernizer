from dataclasses import dataclass


@dataclass
class RouterInterface:
    device: str
    interface: str
    ip: str | None = None
    hsrp_virtual_ip: str | None = None