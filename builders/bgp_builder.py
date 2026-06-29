from models.bgp_route import BGPRoute


class BGPBuilder:

    def __init__(self, graph):
        self.graph = graph

    def add_routes(self, routes: list[BGPRoute]):

        for route in routes:

            prefix_node = self.graph.add_node(
                "Prefix",
                route.prefix,
                {
                    "next_hop": route.next_hop,
                    "vrf": route.vrf,
                    "router": route.source_router,
                    "as_path": route.as_path,
                    "local_pref": route.local_pref,
                    "med": route.med,
                    "origin": route.origin,
                    "raw": route.raw
                }
            )

            if route.source_router:
                router_node = self.graph.add_node(
                    "Router",
                    route.source_router
                )

                self.graph.add_relationship(
                    router_node,
                    prefix_node,
                    "LEARNS_BGP_PREFIX"
                )