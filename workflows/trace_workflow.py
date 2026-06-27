from engines.topology_engine import TopologyEngine

from models.explanation import Explanation
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
        explanation = Explanation()

        security = self.twin.security.is_permitted(
            source,
            destination,
            protocol,
            service
        )

        explanation.add(
            f"ACL decision: {security.reason}"
        )

        if not security.permitted:
            return TraceResult(
                security=security,
                route=None,
                explanation=explanation
            )

        route_result = None

        if route_destination:
            route = self.twin.route.lookup(
                router,
                vrf,
                route_destination
            )

            if route:
                explanation.add(
                    f"Route matched: {route['prefix']}"
                )

                explanation.add(
                    f"Next hop: {route['next_hop']}"
                )

                next_device = self.topology.resolve_router(
                    route["next_hop"]
                )

                if next_device:
                    explanation.add(
                        f"Next hop resolved to {next_device['router']} VRF {next_device['vrf']}"
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
                explanation.add("No route matched")

                route_result = RouteResult(
                    matched=False,
                    hop=None
                )

        return TraceResult(
            security=security,
            route=route_result,
            explanation=explanation
        )