from dataclasses import dataclass, field


@dataclass
class ForwardingResult:
    resolved: bool
    method: str
    device: str | None = None
    device_type: str | None = None
    interface: str | None = None
    reason: str | None = None
    candidates: list = field(default_factory=list)