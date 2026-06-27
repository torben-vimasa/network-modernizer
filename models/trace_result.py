from dataclasses import dataclass

from models.security_result import SecurityResult
from models.route_result import RouteResult
from models.explanation import Explanation




@dataclass
class TraceResult:

    security: SecurityResult

    route: RouteResult | None = None
    explanation: Explanation | None = None
