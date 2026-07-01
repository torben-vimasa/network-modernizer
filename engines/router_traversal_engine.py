from models.traversal_target import TraversalTarget


class RouterTraversalEngine:

    def __init__(self, twin):
        self.twin = twin

    def traverse(
        self,
        router,
        vrf,
        destination
    ):

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

        return TraversalTarget(
            device_name=router,
            device_type="Router",
            vrf=vrf,
            method="route_lookup",
            confidence="high",
            reason=f"Matched route {route['prefix']} via {route['next_hop']}",
            resolved=True
        )