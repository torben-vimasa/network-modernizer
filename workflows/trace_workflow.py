from engines.resolver_engine import ResolverEngine
from engines.topology_engine import TopologyEngine

from models.explanation import Explanation
from models.hop import Hop
from models.route_result import RouteResult
from models.trace_result import TraceResult
from models.packet import Packet


class TraceWorkflow:

    def __init__(self, twin):
        self.twin = twin
        self.topology = TopologyEngine(twin.graph)
        self.resolver = ResolverEngine(twin.graph)

    def trace(
        self,
        source,
        destination,
        protocol=None,
        service=None,
        router=None,
        vrf=None,
        route_destination=None,
        max_hops=5,
    ):
        if isinstance(source, Packet):
            packet = source

            source = packet.source
            destination = packet.destination
            protocol = packet.protocol
            service = packet.service
            router = packet.current_router
            vrf = packet.current_vrf
            route_destination = packet.destination
        else:
            packet = Packet(
                source=source,
                destination=route_destination or destination,
                protocol=protocol,
                service=service,
                current_router=router,
                current_vrf=vrf
            )
        
        explanation = Explanation()
        packet.add_history("Trace started")
        hops = []

        security = self.twin.security.is_permitted(
            source,
            destination,
            protocol,
            service
        )

        explanation.add(f"ACL decision: {security.reason}")
        packet.add_history(f"ACL decision: {security.reason}")

        if isinstance(source, Packet):
            packet = source

            source = packet.source
            destination = packet.destination
            protocol = packet.protocol
            service = packet.service
            router = packet.current_router
            vrf = packet.current_vrf
            route_destination = packet.destination
        else:
            packet = Packet(
                source=source,
                destination=route_destination or destination,
                protocol=protocol,
                service=service,
                current_router=router,
                current_vrf=vrf
            )

        if not security.permitted:
            return TraceResult(
                security=security,
                route=None,
                hops=hops,
                explanation=explanation
            )

        current_router = router
        current_vrf = vrf
        last_route_result = None
        visited = set()

        for hop_number in range(1, max_hops + 1):

            if not current_router or not current_vrf or not route_destination:
                explanation.add("Trace stopped: missing router, VRF or route destination")
                break

            visit_key = f"{current_router}:{current_vrf}:{route_destination}"

            if visit_key in visited:
                explanation.add(f"Trace stopped: loop detected at {current_router} VRF {current_vrf}")
                break

            visited.add(visit_key)

            route = self.twin.route.lookup(
                current_router,
                current_vrf,
                route_destination
            )

            if not route:
                explanation.add(f"No route matched on {current_router} VRF {current_vrf}")

                last_route_result = RouteResult(
                    matched=False,
                    hop=None
                )
                break

            explanation.add(
                f"Hop {hop_number}: {current_router} VRF {current_vrf} matched route {route['prefix']}"
            )

            packet.add_history(
                f"Hop {hop_number}: {current_router} VRF {current_vrf} matched route {route['prefix']}"
            )

            explanation.add(
                f"Hop {hop_number}: next hop {route['next_hop']}"
            )

            packet.next_hop = route["next_hop"]
            packet.add_history(f"Hop {hop_number}: next hop {route['next_hop']}")

            next_device = self.topology.resolve_router(
                route["next_hop"]
            )

            hop = Hop(
                router=current_router,
                vrf=current_vrf,
                route=route["prefix"],
                next_hop=route["next_hop"]
            )

            hops.append(hop)

            last_route_result = RouteResult(
                matched=True,
                hop=hop
            )

            if not next_device:
                resolution = self.resolver.resolve_ip(route["next_hop"])

                explanation.add(
                    f"Trace stopped: next hop {route['next_hop']} could not be directly resolved"
                )

                explanation.add(
                    f"Resolver: {resolution['reason']} ({resolution['confidence']} confidence)"
                )

                if resolution.get("references"):
                    for ref in resolution["references"][:3]:
                        explanation.add(
                            f"Evidence: {ref['router']} VRF {ref['vrf']} routes {ref['prefix']} via {route['next_hop']}"
                        )

                break

            explanation.add(
                f"Hop {hop_number}: next hop resolved to {next_device['router']} VRF {next_device['vrf']}"
            )

            current_router = next_device["router"]
            current_vrf = next_device["vrf"]

        return TraceResult(
            security=security,
            route=last_route_result,
            hops=hops,
            explanation=explanation
        )