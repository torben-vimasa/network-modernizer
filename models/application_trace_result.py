from dataclasses import dataclass, field


@dataclass
class ApplicationTraceResult:

    application: str

    criticality: str

    max_outage_minutes: int | None

    traces: list = field(default_factory=list)