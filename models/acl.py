from dataclasses import dataclass, field

from models.acl_rule import ACLRule


@dataclass
class ACL:

    name: str

    interface: str | None = None

    direction: str | None = None

    rules: list[ACLRule] = field(default_factory=list)