import ipaddress

from models.bgp_result import BGPResult
from models.bgp_route import BGPRoute


class BGPEngine:

    def __init__(self, routes=None, graph=None):
        self.routes = routes or []
        self.graph = graph

    def lookup(self, destination, vrf=None):

        routes = self.routes

        if self.graph:
            routes = self._routes_from_graph()

        ip = ipaddress.ip_address(destination)

        matches = []

        for route in routes:

            if vrf and route.vrf != vrf:
                continue

            network = ipaddress.ip_network(route.prefix, strict=False)

            if ip in network:
                matches.append((network.prefixlen, route))

        if not matches:
            return BGPResult(
                matched=False,
                route=None,
                reason="No BGP route matched"
            )

        best = sorted(
            matches,
            key=lambda item: item[0],
            reverse=True
        )[0][1]

        return BGPResult(
            matched=True,
            route=best,
            reason="Best BGP route selected by longest prefix match"
        )

    def _routes_from_graph(self):

        routes = []

        for node in self.graph.find_by_type("Prefix"):

            routes.append(
                BGPRoute(
                    prefix=node.name,
                    next_hop=node.properties.get("next_hop"),
                    as_path=node.properties.get("as_path"),
                    local_pref=node.properties.get("local_pref"),
                    med=node.properties.get("med"),
                    origin=node.properties.get("origin"),
                    source_router=node.properties.get("router"),
                    vrf=node.properties.get("vrf"),
                    raw=node.properties.get("raw")
                )
            )

        return routes