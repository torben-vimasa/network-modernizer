from dataclasses import dataclass


@dataclass
class Interface:

    name: str

    vrf: str

    ip: str

    prefix: str | None = None

    description: str | None = None

    hsrp_virtual_ip: str | None = None

    hsrp_state: str | None = None

    hsrp_priority: int | None = None
