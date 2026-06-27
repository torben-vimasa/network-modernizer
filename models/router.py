from dataclasses import dataclass, field

from models.interface import Interface


@dataclass
class Router:

    name: str

    interfaces: list[Interface] = field(default_factory=list)