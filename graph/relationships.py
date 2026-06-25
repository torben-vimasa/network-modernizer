from dataclasses import dataclass


@dataclass
class Relationship:
    source: str
    target: str
    type: str
    properties: dict