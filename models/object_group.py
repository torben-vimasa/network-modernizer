from dataclasses import dataclass, field


@dataclass
class ObjectGroup:

    name: str

    members: list[str] = field(default_factory=list)