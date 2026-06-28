from dataclasses import dataclass

from models.nat_rule import NATRule


@dataclass
class NATResult:

    matched: bool
    rule: NATRule | None = None

    source_before: str | None = None
    source_after: str | None = None

    destination_before: str | None = None
    destination_after: str | None = None

    reason: str | None = None