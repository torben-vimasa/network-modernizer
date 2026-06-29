from dataclasses import dataclass


@dataclass
class FirewallHop:

    firewall: str | None = None

    context: str | None = None

    ingress_interface: str | None = None

    ip: str | None = None

    subnet: str | None = None

    reason: str | None = None