from dataclasses import dataclass, field
from typing import Any


@dataclass
class TraversalState:

    #
    # Current traversal position
    #
    router: str | None
    vrf: str | None
    destination: str

    ingress_interface: str | None = None
    phase: str = "routing"
    pending_firewall: dict | None = None

    #
    # Packet and trace state
    #
    packet: Any = None
    security: Any = None
    last_route_result: Any = None

    hops: list = field(default_factory=list)
    firewall_hops: list = field(default_factory=list)
    network_hops: list = field(default_factory=list)

    visited: set = field(default_factory=set)

    finished: bool = False
    destination_reached: bool = False
    inventory_boundary: bool = False
    stop_reason: str | None = None

    def key(self):
        return (
            f"{self.router}:"
            f"{self.vrf}:"
            f"{self.ingress_interface}:"
            f"{self.destination}:"
            f"{self.phase}"
        )

    def has_valid_routing_start(self):
        return bool(
            self.router
            and self.vrf
            and self.destination
        )

    def mark_finished(
        self,
        reason=None,
        destination_reached=False,
        inventory_boundary=False
    ):
        self.finished = True
        self.stop_reason = reason
        self.destination_reached = destination_reached
        self.inventory_boundary = inventory_boundary

    def set_router_target(
        self,
        router,
        vrf,
        ingress_interface=None
    ):
        self.router = router
        self.vrf = vrf
        self.ingress_interface = ingress_interface
        self.phase = "routing"

        if self.packet is not None:
            self.packet.current_router = router
            self.packet.current_vrf = vrf
            self.packet.ingress_interface = ingress_interface