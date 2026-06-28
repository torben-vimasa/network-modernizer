from dataclasses import dataclass, field

from models.application_flow import ApplicationFlow


@dataclass
class Application:

    name: str

    business_service: str | None = None

    owner: str | None = None

    criticality: str = "normal"

    max_outage_minutes: int | None = None

    description: str | None = None

    flows: list[ApplicationFlow] = field(default_factory=list)