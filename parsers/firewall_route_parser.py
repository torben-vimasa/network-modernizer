from models.route_entry import RouteEntry


class FirewallRouteParser:

    def parse(self, lines):

        hostname = "UnknownFirewall"
        routes = []

        for raw_line in lines:

            line = raw_line.strip()

            if line.startswith("hostname "):
                hostname = line.split(maxsplit=1)[1]
                continue

            #
            # Cisco FTD:
            # route <interface> <network> <mask> <next-hop> [metric]
            #
            if not line.startswith("route "):
                continue

            parts = line.split()

            if len(parts) < 5:
                continue

            interface = parts[1]
            network = parts[2]
            mask = parts[3]
            next_hop = parts[4]

            metric = 1

            if len(parts) >= 6:
                try:
                    metric = int(parts[5])
                except ValueError:
                    pass

            routes.append(
                RouteEntry(
                    router=hostname,
                    vrf="global",
                    prefix=f"{network}/{mask}",
                    next_hop=next_hop,
                    protocol="static",
                    interface=interface,
                    metric=metric
                )
            )

        return routes