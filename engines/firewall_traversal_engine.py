from models.firewall_traversal_result import FirewallTraversalResult


class FirewallTraversalEngine:

    def __init__(self, twin):
        self.twin = twin

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

        #
        # ACL
        #

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

        #
        # NAT
        #

        translated_packet, nat = self.twin.nat.translate(packet)

        result.nat = nat

        result.source_after = translated_packet.source
        result.destination_after = translated_packet.destination

        result.permitted = True

        result.reason = "ACL + NAT completed"

        return result