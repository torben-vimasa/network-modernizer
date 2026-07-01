from dataclasses import dataclass


@dataclass
class TraversalTarget:

    device_name: str
    device_type: str

    interface: str | None = None
    vrf: str | None = None

    method: str | None = None
    confidence: str | None = None
    reason: str | None = None

    resolved: bool = True