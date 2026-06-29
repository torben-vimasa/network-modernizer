from dataclasses import dataclass


@dataclass
class NATRule:

    name: str | None = None

    source_original: str | None = None
    source_translated: str | None = None

    destination_original: str | None = None
    destination_translated: str | None = None

    service_original: str | None = None
    service_translated: str | None = None

    direction: str | None = None
    section: str | None = None

    reason: str | None = None
    raw: str | None = None