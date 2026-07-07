from dataclasses import dataclass


@dataclass
class HSRPState:
    device: str
    interface: str
    virtual_ip: str | None = None
    state: str | None = None
    active_router: str | None = None
    standby_router: str | None = None
    priority: str | None = None