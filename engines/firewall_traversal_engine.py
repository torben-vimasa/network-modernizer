from engines.firewall_route_engine import FirewallRouteEngine
from engines.interface_resolution_engine import InterfaceResolutionEngine
from engines.resolver_engine import ResolverEngine
from engines.topology_traversal_engine import TopologyTraversalEngine

from models.firewall_traversal_result import FirewallTraversalResult


class FirewallTraversalEngine:

    def __init__(self, twin, routes=None, interfaces=None):
        self.twin = twin
        self.routes = routes or []
        self.interfaces = interfaces or []
        self.resolver = ResolverEngine(twin.graph)
        self.topology = TopologyTraversalEngine(twin.graph)

    def traverse(self, firewall_hop, packet):

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
            packet.service,
            context=result.context,
            ingress_interface=result.ingress_interface,
            defer_global_acl=True
        )

        result.security = security

        if not security.permitted:
            result.output_packet = packet
            result.reason = security.reason
            return result

        translated_packet, nat = self.twin.nat.translate(packet)

        result.nat = nat
        result.source_after = translated_packet.source
        result.destination_after = translated_packet.destination

        route_result = FirewallRouteEngine(
            self.routes
        ).lookup(
            translated_packet.destination,
            context=result.context,
            ingress_interface=result.ingress_interface
        )

        if (
            not route_result
            or not route_result.matched
            or not route_result.route
        ):
            result.output_packet = translated_packet
            result.permitted = False
            result.reason = (
                f"No firewall route found for "
                f"{translated_packet.destination} "
                f"in context {result.context}"
            )
            return result

        result.route = route_result.route.prefix
        result.next_hop = route_result.next_hop

        translated_packet.next_hop = route_result.next_hop

        #
        # Resolve firewall egress interface
        #
        if route_result.egress_interface:
            result.egress_interface = route_result.egress_interface
        else:
            interface = InterfaceResolutionEngine(
                self.interfaces
            ).resolve_egress(
                route_result.next_hop
            )

            if interface:
                result.egress_interface = (
                    interface.get("nameif")
                    or interface.get("name")
                    or interface.get("interface")
                )

            #
            # Final context-aware security evaluation.
            #
            # FTD global ACL rules may specify both source_ifc
            # and destination_ifc. destination_ifc can only be
            # validated after firewall routing has resolved egress.
            #
            final_security = self.twin.security.is_permitted(
                packet.source,
                packet.destination,
                packet.protocol,
                packet.service,
                context=result.context,
                ingress_interface=result.ingress_interface,
                egress_interface=result.egress_interface
            )

            result.security = final_security

            if not final_security.permitted:
                result.output_packet = translated_packet
                result.permitted = False
                result.reason = final_security.reason
                return result


                #
        # A route with an egress interface but no next hop
        # represents direct Layer-2 delivery on a connected network.
        #
        if (
            route_result.next_hop is None
            and result.egress_interface
        ):
            result.destination_reached = True
            result.permitted = True
            result.output_packet = translated_packet
            result.reason = (
                "Destination reached through directly connected "
                f"interface {result.egress_interface}"
            )
            return result

        result.destination_reached = False

        topology_result = None

        
        if result.egress_interface:
            topology_result = self.topology.find_connected_device(
                context=result.context,
                interface_name=result.egress_interface
            )

        if topology_result and topology_result.get("found"):
            result.next_device = {
                "resolved": True,
                "method": "topology_connected_to",
                "router": topology_result.get("router"),
                "vrf": topology_result.get("connected_vrf"),
                "interface": topology_result.get("connected_interface"),
                "reason": topology_result.get("reason"),
                "confidence": "high",
                "references": []
            }

            result.target = topology_result.get("target")

            result.output_packet = translated_packet
            result.permitted = True
            result.reason = "ACL + NAT + firewall route + egress + next-device completed"
            return result

        result.next_device = self.resolver.resolve_ip(
            route_result.next_hop
        )

        if (
            result.next_device
            and not result.next_device.get("resolved")
            and result.egress_interface
        ):
            result.next_device["method"] = "inventory_boundary"
            result.next_device["inventory_boundary"] = True
            result.next_device["reason"] = (
                f"Next-hop {route_result.next_hop} is reachable via firewall "
                f"egress interface {result.egress_interface}, but no managed "
                f"device interface owns that IP in the current inventory"
            )
            result.next_device["confidence"] = "medium"

        result.output_packet = translated_packet
        result.permitted = True
        result.reason = "ACL + NAT + firewall route + egress + next-device completed"

        return result