from engines.topology_engine import TopologyEngine

from models.hop import Hop
from models.route_result import RouteResult
from models.trace_result import TraceResult


class TraceWorkflow:

    def __init__(self, twin):

        self.twin = twin
        self.topology = TopologyEngine()

    def trace(
        self,
        source,
        destination,
        protocol=None,
        service=None,
        router=None,
        vrf=None,
        route_destination=None,
    ):

        #
        # Step 1 - Security
        #
        security = self.twin.security.is_permitted(
            source,
            destination,
            protocol,
            service
        )

        if not security.permitted:

            return TraceResult(
                security=security,
                route=None
            )

        #
        # Step 2 - Routing
        #
        route_result = None

        if route_destination:

            route = self.twin.route.lookup(
                router,
                vrf,
                route_destination
            )

            if route:

                next_device = self.topology.resolve_router(
                    route["next_hop"]
                )

                hop = Hop(
                    router=next_device["router"] if next_device else router,
                    vrf=next_device["vrf"] if next_device else vrf,
                    route=route["prefix"],
                    next_hop=route["next_hop"]
                )

                route_result = RouteResult(
                    matched=True,
                    hop=hop
                )

            else:

                route_result = RouteResult(
                    matched=False,
                    hop=None
                )

        #
        # Final result
        #
        return TraceResult(
            security=security,
            route=route_result
        )