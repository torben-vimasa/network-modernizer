import ipaddress

from models.bgp_result import BGPResult


class BGPEngine:

    def __init__(self, routes=None):
        self.routes = routes or []

    def lookup(self, destination, vrf=None):

        ip = ipaddress.ip_address(destination)

        matches = []

        for route in self.routes:

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