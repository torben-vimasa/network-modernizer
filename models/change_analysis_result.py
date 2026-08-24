from dataclasses import dataclass, field

from models.impact_result import ImpactResult
from models.proposed_change import ProposedChange


@dataclass
class ChangeAnalysisResult:

    source: str
    destination: str

    change: ProposedChange

    current_impact: ImpactResult

    change_touches_primary_path: bool = False
    change_touches_candidate_path: bool = False

    affected_devices: list[str] = field(
        default_factory=list
    )

    affected_vrfs: list[str] = field(
        default_factory=list
    )

    primary_route_matches: list[dict] = field(
        default_factory=list
    )

    candidate_route_matches: list[dict] = field(
        default_factory=list
    )

    assessment: str | None = None
    confidence: str | None = None