from dataclasses import dataclass

from models.security_result import SecurityResult
from models.route_result import RouteResult


@dataclass
class TraceResult:

    security: SecurityResult

    route: RouteResult | None = None