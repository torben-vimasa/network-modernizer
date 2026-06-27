from dataclasses import dataclass
from models.hop import Hop


@dataclass
class RouteResult:

    matched: bool

    hop: Hop | None