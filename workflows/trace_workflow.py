from engines.firewall_traversal_engine import FirewallTraversalEngine
from engines.resolver_engine import ResolverEngine
from engines.topology_engine import TopologyEngine

from models.explanation import Explanation
from models.firewall_hop import FirewallHop
from models.hop import Hop
from models.network_hop import NetworkHop
from models.packet import Packet
from models.route_result import RouteResult
from models.trace_result import TraceResult
from models.traversal_state import TraversalState


class TraceWorkflow:

    def __init__(self, twin):
        self.twin = twin
        self.topology = TopologyEngine(twin.graph)
        self.resolver = ResolverEngine(twin.graph)

    def trace(
        self,
        source,
        destination=None,
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
            router = packet.current_router or router
            vrf = packet.current_vrf or vrf
            route_destination = route_destination or packet.destination
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
        firewall_hops = []
        network_hops = []

        security = self.twin.security.is_permitted(
            source,
            destination,
            protocol,
            service
        )

        explanation.add(f"ACL decision: {security.reason}")

        if not security.permitted:
            return TraceResult(
                security=security,
                route=None,
                hops=hops,
                firewall_hops=firewall_hops,
                network_hops=network_hops,
                explanation=explanation
            )

        translated_packet, nat_result = self.twin.nat.translate(packet)

        explanation.add(f"NAT decision: {nat_result.reason}")

        if nat_result.matched:
            explanation.add(
                f"NAT source: {nat_result.source_before} -> {nat_result.source_after}"
            )
            explanation.add(
                f"NAT destination: {nat_result.destination_before} -> {nat_result.destination_after}"
            )

        packet = translated_packet

        current_router = router
        current_vrf = vrf
        last_route_result = None
        visited = set()

        for hop_number in range(1, max_hops + 1):

            if not current_router or not current_vrf or not route_destination:
                explanation.add("Trace stopped: missing router, VRF or route destination")
                break

            state = TraversalState(
                router=current_router,
                vrf=current_vrf,
                ingress_interface=getattr(packet, "ingress_interface", None),
                destination=route_destination,
                phase="routing"
            )

            visit_key = state.key()

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
            explanation.add(
                f"Hop {hop_number}: next hop {route['next_hop']}"
            )

            packet.next_hop = route["next_hop"]

            hop = Hop(
                router=current_router,
                vrf=current_vrf,
                route=route["prefix"],
                next_hop=route["next_hop"]
            )

            hops.append(hop)

            network_hops.append(
                NetworkHop(
                    hop_number=len(network_hops) + 1,
                    hop_type="router",
                    device=current_router,
                    vrf=current_vrf,
                    route=route["prefix"],
                    next_hop=route["next_hop"],
                    reason="Matched route"
                )
            )

            last_route_result = RouteResult(
                matched=True,
                hop=hop
            )

            next_device = self.topology.resolve_router(
                route["next_hop"]
            )

            if not next_device:
                resolution = self.resolver.resolve_ip(route["next_hop"])

                if resolution.get("resolved") and resolution.get("method") == "asa_interface":

                    fw_hop = FirewallHop(
                        firewall=resolution.get("firewall"),
                        context=resolution.get("context"),
                        ingress_interface=resolution.get("interface"),
                        ip=resolution.get("ip"),
                        subnet=resolution.get("subnet"),
                        reason="Next-hop resolved to ASA interface"
                    )

                    firewall_hops.append(fw_hop)

                    traversal = FirewallTraversalEngine(
                        twin=self.twin,
                        routes=getattr(self.twin, "firewall_routes", []),
                        interfaces=getattr(self.twin, "firewall_interfaces", [])
                    ).traverse(
                        fw_hop,
                        Packet(
                            source=source,
                            destination=route_destination,
                            protocol=protocol,
                            service=service
                        )
                    )

                    network_hops.append(
                        NetworkHop(
                            hop_number=len(network_hops) + 1,
                            hop_type="firewall",
                            device=traversal.firewall,
                            context=traversal.context,
                            ingress_interface=traversal.ingress_interface,
                            egress_interface=traversal.egress_interface,
                            ip=resolution.get("ip"),
                            subnet=resolution.get("subnet"),
                            route=traversal.route,
                            next_hop=traversal.next_hop,
                            reason=traversal.reason,
                            acl_rule=str(traversal.security.rule_id) if traversal.security and getattr(traversal.security, "rule_id", None) else None,
                            nat_rule=traversal.nat.rule.name if traversal.nat and traversal.nat.rule else None,
                            route_lookup=traversal.route,
                            policy="permit" if traversal.permitted else "deny"
                        )
                    )

                    explanation.add(
                        f"Trace reached ASA interface {resolution['context']}:{resolution['interface']}"
                    )
                    explanation.add(
                        f"Firewall traversal: {traversal.reason}"
                    )
                    explanation.add(
                        f"Firewall egress: {traversal.egress_interface}"
                    )
                    explanation.add(
                        f"Firewall next-hop: {traversal.next_hop}"
                    )

                    if getattr(traversal, "destination_reached", False):
                        explanation.add(
                            f"Destination reached via firewall route {traversal.route}"
                        )
                        break

                    if traversal.next_device and traversal.next_device.get("resolved"):
                        method = traversal.next_device.get("method")

                        if method in ["router_inventory", "topology_connected_to"]:
                            current_router = traversal.next_device.get("router")
                            current_vrf = traversal.next_device.get("vrf")
                            if not current_vrf:
                                current_vrf = vrf

                            packet = traversal.output_packet
                            packet.ingress_interface = traversal.next_device.get("interface")

                            explanation.add(
                                f"Trace continues to router {current_router} VRF {current_vrf}"
                            )

                            continue

                    if traversal.next_device:
                        explanation.add(
                            f"Firewall next-hop resolution: {traversal.next_device.get('reason')}"
                        )
                        explanation.add(
                            f"Firewall next-hop resolution method: {traversal.next_device.get('method')}"
                        )
                        explanation.add(
                            f"Firewall next-hop resolution confidence: {traversal.next_device.get('confidence')}"
                        )

                    explanation.add("Trace stopped after firewall traversal: missing next-router inventory")
                    break

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
            firewall_hops=firewall_hops,
            network_hops=network_hops,
            explanation=explanation
        )

        