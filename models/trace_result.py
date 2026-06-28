from dataclasses import dataclass, field

from models.security_result import SecurityResult
from models.route_result import RouteResult
from models.hop import Hop
from models.explanation import Explanation


@dataclass
class TraceResult:
    security: SecurityResult
    route: RouteResult | None = None
    hops: list[Hop] = field(default_factory=list)
    explanation: Explanation | None = None