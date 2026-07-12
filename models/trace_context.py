from dataclasses import dataclass, field
from typing import Any

from models.traversal_state import TraversalState


@dataclass
class TraceContext:

    #
    # Immutable input
    #
    source: str
    destination: str
    protocol: str | None = None
    service: str | None = None

    #
    # Runtime packet
    #
    packet: Any = None

    #
    # Current location
    #
    current_router: str | None = None
    current_vrf: str | None = None

    #
    # Current traversal
    #
    traversal: TraversalState | None = None

    #
    # Results
    #
    security: Any = None
    last_route: Any = None

    hops: list = field(default_factory=list)
    firewall_hops: list = field(default_factory=list)
    network_hops: list = field(default_factory=list)

    #
    # Runtime
    #
    visited: set = field(default_factory=set)

    finished: bool = False
    destination_reached: bool = False

    stop_reason: str | None = None

    def start_traversal(
        self,
        router,
        vrf,
        ingress_interface=None
    ):

        self.current_router = router
        self.current_vrf = vrf

        self.traversal = TraversalState(
            router=router,
            vrf=vrf,
            destination=self.destination,
            ingress_interface=ingress_interface
        )

    def move_to_router(
        self,
        router,
        vrf,
        ingress_interface=None
    ):

        self.current_router = router
        self.current_vrf = vrf

        self.traversal = TraversalState(
            router=router,
            vrf=vrf,
            destination=self.destination,
            ingress_interface=ingress_interface
        )

    def finish(
        self,
        reason=None,
        destination_reached=False
    ):

        self.finished = True
        self.stop_reason = reason
        self.destination_reached = destination_reached