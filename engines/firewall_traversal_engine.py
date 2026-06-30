from engines.firewall_route_engine import FirewallRouteEngine

from models.firewall_traversal_result import FirewallTraversalResult


class FirewallTraversalEngine:

    def __init__(self, twin, routes=None):
        self.twin = twin
        self.routes = routes or []

    def traverse(
        self,
        firewall_hop,
        packet
    ):

        result = FirewallTraversalResult()

        result.firewall = firewall_hop.firewall
        result.context = firewall_hop.context
        result.ingress_interface = firewall_hop.ingress_interface

        result.source_before = packet.source
        result.destination_before = packet.destination

        security = self.twin.security.is_permitted(
            packet.source,
            packet.destination,
            packet.protocol,
            packet.service
        )

        result.security = security

        if not security.permitted:
            result.reason = security.reason
            return result

        translated_packet, nat = self.twin.nat.translate(packet)

        result.nat = nat
        result.source_after = translated_packet.source
        result.destination_after = translated_packet.destination

        route_result = FirewallRouteEngine(self.routes).lookup(
            translated_packet.destination
        )

        if route_result.matched:
            result.route = route_result.route.prefix
            result.next_hop = route_result.next_hop
            result.egress_interface = route_result.egress_interface

        result.permitted = True
        result.reason = "ACL + NAT + firewall route completed"

        return result