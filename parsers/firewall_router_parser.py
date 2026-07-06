import ipaddress

from models.route_entry import RouteEntry


class FirewallRouteParser:

    def parse(self, lines, device="BHASA1", context="BDK-Mgmt"):

        routes = []

        for raw_line in lines:
            line = raw_line.strip()

            if not line.startswith("route "):
                continue

            parts = line.split()

            if len(parts) < 5:
                continue

            interface = parts[1]
            network = parts[2]
            mask = parts[3]
            next_hop = parts[4]

            prefix = str(
                ipaddress.ip_network(
                    f"{network}/{mask}",
                    strict=False
                )
            )

            route = RouteEntry(
                router=device,
                vrf=context,
                prefix=prefix,
                next_hop=next_hop,
                protocol="static"
            )

            route.interface = interface
            route.egress_interface = interface

            routes.append(route)

        return routes