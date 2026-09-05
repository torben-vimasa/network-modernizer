from dataclasses import dataclass, field

from models.dependency import Dependency
from models.dependency_hint import DependencyHint
from models.dependency_state import DependencyState


@dataclass
class DependencyReportEntry:

    dependency: Dependency

    hint: DependencyHint | None = None

    state: DependencyState | None = None


@dataclass
class DependencyReport:

    network: str

    direction: str = "both"

    service: str | None = None

    action: str = "permit"

    entries: list[DependencyReportEntry] = field(
        default_factory=list
    )

    dependency_count: int = 0

    inbound_count: int = 0

    outbound_count: int = 0

    high_confidence_count: int = 0

    medium_confidence_count: int = 0

    low_confidence_count: int = 0

    full_coverage_count: int = 0

    sampled_coverage_count: int = 0

    not_applicable_coverage_count: int = 0

    target_count: int = 0

    attempted_target_count: int = 0

    evidence_target_count: int = 0

    evidence_class_counts: dict[str, int] = field(
        default_factory=dict
    )

    observation_state_counts: dict[str, int] = field(
        default_factory=dict
    )
