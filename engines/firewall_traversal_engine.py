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

        #
        # ---------------------------------------------------------
        # 1. Initial security check
        #
        # Classic ASA interface ACLs can be evaluated immediately.
        #
        # FTD global ACLs may require destination_ifc, so their
        # evaluation is deferred until routing resolves egress.
        # ---------------------------------------------------------
        #
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
            result.permitted = False
            result.reason = security.reason
            return result

        #
        # ---------------------------------------------------------
        # 2. NAT
        # ---------------------------------------------------------
        #
        translated_packet, nat = self.twin.nat.translate(
        packet,
        context=result.context,
        ingress_interface=result.ingress_interface
        )

        result.nat = nat
        result.source_after = translated_packet.source
        result.destination_after = translated_packet.destination

        #
        # ---------------------------------------------------------
        # 3. Firewall routing lookup
        # ---------------------------------------------------------
        #
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
        # ---------------------------------------------------------
        # 4. Resolve firewall egress interface
        # ---------------------------------------------------------
        #
        if route_result.egress_interface:

            result.egress_interface = (
                route_result.egress_interface
            )

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
        # ---------------------------------------------------------
        # 5. Final security evaluation
        #
        # ONLY for FTD/global ACL.
        #
        # Classic ASA interface ACLs were already evaluated above
        # using ingress_interface and must NOT be evaluated again.
        # ---------------------------------------------------------
        #
        firewall = self.twin.graph.find(
            "Firewall",
            result.context
        )

        has_global_acl = False

        if firewall:

            for relation, neighbor in self.twin.graph.neighbors(
                firewall.id
            ):

                if (
                    relation == "USES_GLOBAL_ACL"
                    and neighbor.type == "ACL"
                ):
                    has_global_acl = True
                    break

        if has_global_acl:

            final_security = self.twin.security.is_permitted(
                translated_packet.source,
                translated_packet.destination,
                translated_packet.protocol,
                translated_packet.service,
                context=result.context,
                ingress_interface=result.ingress_interface,
                egress_interface=result.egress_interface,
                defer_global_acl=False
            )

            result.security = final_security

            if not final_security.permitted:
                result.output_packet = translated_packet
                result.permitted = False
                result.reason = final_security.reason
                return result

        #
        # ---------------------------------------------------------
        # 6. Directly connected destination
        # ---------------------------------------------------------
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

        #
        # ---------------------------------------------------------
        # 7. Topology-based continuation
        # ---------------------------------------------------------
        #
        topology_result = None

        if result.egress_interface:

            topology_result = (
                self.topology.find_connected_device(
                    context=result.context,
                    interface_name=result.egress_interface
                )
            )

        if (
            topology_result
            and topology_result.get("found")
        ):

            result.next_device = {
                "resolved": True,
                "method": "topology_connected_to",
                "router": topology_result.get("router"),
                "vrf": topology_result.get(
                    "connected_vrf"
                ),
                "interface": topology_result.get(
                    "connected_interface"
                ),
                "reason": topology_result.get("reason"),
                "confidence": "high",
                "references": []
            }

            result.target = topology_result.get(
                "target"
            )

            result.output_packet = translated_packet
            result.permitted = True

            result.reason = (
                "ACL + NAT + firewall route + "
                "egress + next-device completed"
            )

            return result

        #
        # ---------------------------------------------------------
        # 8. Resolve next-hop from inventory
        # ---------------------------------------------------------
        #
        result.next_device = self.resolver.resolve_ip(
            route_result.next_hop
        )

        #
        # Unresolved next-hop = inventory boundary,
        # not a security deny.
        #
        if (
            result.next_device
            and not result.next_device.get("resolved")
        ):

            result.output_packet = translated_packet
            result.permitted = True

            result.reason = (
                "ACL + NAT + firewall route completed; "
                f"next-hop {route_result.next_hop} "
                "could not be resolved in inventory"
            )

            return result

        #
        # Successful next-hop resolution
        #
        result.output_packet = translated_packet
        result.permitted = True

        result.reason = (
            "ACL + NAT + firewall route + "
            "egress + next-device completed"
        )

        return result