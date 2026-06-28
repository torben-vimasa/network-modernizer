from dataclasses import dataclass


@dataclass
class ApplicationFlow:

    source: str

    destination: str

    protocol: str

    service: str

    description: str | None = None