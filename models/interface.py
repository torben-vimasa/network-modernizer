from dataclasses import dataclass


@dataclass
class Interface:

    name: str

    vrf: str

    ip: str

    prefix: str | None = None

    description: str | None = None