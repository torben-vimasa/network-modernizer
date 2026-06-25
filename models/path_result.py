from dataclasses import dataclass, field


@dataclass
class PathResult:

    source_ip: str
    destination_ip: str

    source_matches: list = field(default_factory=list)
    destination_matches: list = field(default_factory=list)

    vrfs: list = field(default_factory=list)
    firewalls: list = field(default_factory=list)
    routers: list = field(default_factory=list)

    findings: list = field(default_factory=list)
    warnings: list = field(default_factory=list)

    confidence: int = 0