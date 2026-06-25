from dataclasses import dataclass, field


@dataclass
class ACLRule:
    acl_name: str

    sequence: int

    action: str

    protocol: str

    source: str

    destination: str

    service: str | None = None

    remark: str | None = None

    hitcnt: int | None = None

    enabled: bool = True

    properties: dict = field(default_factory=dict)