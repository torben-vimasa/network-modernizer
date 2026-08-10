from dataclasses import dataclass, field


@dataclass
class ForwardingResult:
    resolved: bool
    method: str

    device: str | None = None
    device_type: str | None = None
    interface: str | None = None

    reason: str | None = None

    # True when the trace reaches a subnet where the next-hop
    # belongs to infrastructure outside the managed inventory
    inventory_boundary: bool = False

    candidates: list = field(default_factory=list)