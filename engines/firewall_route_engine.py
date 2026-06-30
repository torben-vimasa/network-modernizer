import ipaddress

from models.firewall_route_result import FirewallRouteResult


class FirewallRouteEngine:

    def __init__(self, routes):

        self.routes = routes

    def lookup(self, destination):

        ip = ipaddress.ip_address(destination)

        matches = []

        for route in self.routes:

            network = ipaddress.ip_network(route.prefix, strict=False)

            if ip in network:
                matches.append((network.prefixlen, route))

        if not matches:
            return FirewallRouteResult(
                matched=False,
                reason="No firewall route matched"
            )

        route = sorted(
            matches,
            key=lambda item: item[0],
            reverse=True
        )[0][1]

        return FirewallRouteResult(
            matched=True,
            route=route,
            next_hop=route.next_hop,
            egress_interface=None,
            reason="Firewall route selected by longest prefix match"
        )