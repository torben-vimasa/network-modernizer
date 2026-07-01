import ipaddress

from models.firewall_route_result import FirewallRouteResult


class FirewallRouteEngine:

    def __init__(self, routes):
        self.routes = routes or []

    def lookup(
        self,
        destination,
        context=None,
        ingress_interface=None
    ):

        ip = ipaddress.ip_address(destination)

        matches = []

        for route in self.routes:

            if context and getattr(route, "vrf", None) not in [None, context]:
                continue

            route_ingress = getattr(route, "ingress_interface", None)

            if ingress_interface and route_ingress and route_ingress != ingress_interface:
                continue

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