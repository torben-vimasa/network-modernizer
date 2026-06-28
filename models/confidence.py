from dataclasses import dataclass


@dataclass
class Confidence:

    level: str
    score: float
    reason: str