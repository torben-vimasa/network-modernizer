from dataclasses import dataclass


@dataclass
class ACLMatch:

    firewall: str | None = None

    context: str | None = None

    interface: str | None = None

    acl: str | None = None

    rule: int | None = None

    action: str | None = None

    raw: str | None = None