from dataclasses import dataclass


@dataclass
class StartTarget:

    resolved: bool = False

    device_type: str | None = None

    device: str | None = None

    firewall: str | None = None
    context: str | None = None

    router: str | None = None
    vrf: str | None = None

    interface: str | None = None

    method: str | None = None
    confidence: str | None = None
    reason: str | None = None

    candidates: list | None = None