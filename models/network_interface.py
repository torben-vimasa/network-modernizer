from dataclasses import dataclass


@dataclass
class NetworkInterface:

    device: str

    name: str

    ip: str | None = None
    subnet: str | None = None

    vrf: str | None = None

    interface_type: str | None = None

    raw: str | None = None