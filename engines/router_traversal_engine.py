from models.traversal_target import TraversalTarget


class RouterTraversalEngine:

    def __init__(self, twin):
        self.twin = twin

    def traverse(self, router, vrf, destination):

        route = self.twin.route.lookup(
            router,
            vrf,
            destination
        )

        if not route:
            return TraversalTarget(
                device_name=router,
                device_type="Router",
                vrf=vrf,
                method="route_lookup",
                confidence="low",
                reason=f"No route matched on {router} VRF {vrf}",
                resolved=False
            )

        next_hop = route["next_hop"]

        target = self._resolve_next_hop(next_hop)

        if target:
            return target

        return TraversalTarget(
            device_name=router,
            device_type="Router",
            vrf=vrf,
            method="route_lookup",
            confidence="medium",
            reason=f"Matched route {route['prefix']} via unresolved next-hop {next_hop}",
            resolved=False
        )

    def _resolve_next_hop(self, next_hop):

        for rel in self.twin.graph.relationships:

            if rel.type != "PEERS_WITH":
                continue

            bgp = self.twin.graph.nodes.get(rel.source)
            rif = self.twin.graph.nodes.get(rel.target)

            if not bgp or not rif:
                continue

            if bgp.name != next_hop:
                continue

            router = self._find_parent_router(rif)

            if not router:
                continue

            return TraversalTarget(
                device_name=router.name,
                device_type="Router",
                interface=rif.name,
                vrf=rif.properties.get("vrf"),
                method="bgp_peer_resolution",
                confidence="high",
                reason=f"Next-hop {next_hop} resolved via BGP peer to {router.name}:{rif.name}",
                resolved=True
            )

        return None

    def _find_parent_router(self, interface_node):

        for relation, neighbor in self.twin.graph.neighbors(interface_node.id):

            if relation == "HAS_INTERFACE" and neighbor.type == "Router":
                return neighbor

        return None