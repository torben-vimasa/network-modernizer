from dataclasses import dataclass


@dataclass
class TraversalState:

    router: str
    vrf: str
    destination: str

    ingress_interface: str | None = None
    phase: str = "routing"

    def key(self):
        return (
            f"{self.router}:"
            f"{self.vrf}:"
            f"{self.ingress_interface}:"
            f"{self.destination}:"
            f"{self.phase}"
        )