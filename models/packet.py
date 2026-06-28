from dataclasses import dataclass, field


@dataclass
class Packet:

    source: str
    destination: str

    protocol: str | None = None
    service: str | None = None

    current_router: str | None = None
    current_vrf: str | None = None

    next_hop: str | None = None

    history: list = field(default_factory=list)

    def add_history(self, text):
        self.history.append(text)