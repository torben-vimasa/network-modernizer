from dataclasses import dataclass, field
from models.acl_endpoint import ACLEndpoint


@dataclass
class ACLRule:
    acl_name: str

    sequence: int

    action: str

    protocol: str

    source: ACLEndpoint

    destination: ACLEndpoint

    source_type: str | None = None
    source_value: str | None = None

    destination_type: str | None = None
    destination_value: str | None = None

    service: str | None = None

    remark: str | None = None

    hitcnt: int | None = None

    enabled: bool = True

    properties: dict = field(default_factory=dict)