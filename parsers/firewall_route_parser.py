import ipaddress
import re

from models.route_entry import RouteEntry


class FirewallRouteParser:

    def parse(self, lines):

        hostname = "UnknownFirewall"
        routes = []

        pending_connected = None

        for raw_line in lines:

            line = raw_line.strip()

            if not line:
                continue

            if line.startswith("hostname "):
                hostname = line.split(maxsplit=1)[1]
                continue

            #
            # ---------------------------------------------------------
            # 1. Configured static route
            #
            # route <interface> <network> <mask> <next-hop> [metric]
            # ---------------------------------------------------------
            #
            if line.startswith("route "):

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
                        prefix=self._to_prefix(network, mask),
                        next_hop=next_hop,
                        protocol="static",
                        exit_interface=interface,
                        metric=metric
                    )
                )

                continue

            #
            # ---------------------------------------------------------
            # 2. Operative RIB route with next-hop
            #
            # Examples:
            #
            # B 100.72.36.64 255.255.255.224 [20/50]
            #   via 100.72.33.13, 7w0d
            #
            # or on one line:
            #
            # B 100.72.36.64 255.255.255.224 [20/50]
            #   via 100.72.33.13, interface
            #
            # ---------------------------------------------------------
            #
            match = re.match(
                r"^(?P<code>[A-Z][A-Z0-9*+]*)\s+"
                r"(?P<network>\d+\.\d+\.\d+\.\d+)\s+"
                r"(?P<mask>\d+\.\d+\.\d+\.\d+)"
                r"(?:\s+\[(?P<distance>\d+)/(?P<metric>\d+)\])?"
                r"(?:\s+via\s+(?P<next_hop>\d+\.\d+\.\d+\.\d+))?",
                line
            )

            if match:

                code = match.group("code")
                network = match.group("network")
                mask = match.group("mask")
                next_hop = match.group("next_hop")

                protocol = self._protocol_from_code(code)

                admin_distance = None
                metric = 0

                if match.group("distance"):
                    admin_distance = int(
                        match.group("distance")
                    )

                if match.group("metric"):
                    metric = int(
                        match.group("metric")
                    )

                prefix = self._to_prefix(
                    network,
                    mask
                )

                #
                # Connected/local entries are normally completed
                # by the following line:
                #
                # is directly connected, <interface>
                #
                if code in ("C", "L") and not next_hop:

                    pending_connected = {
                        "router": hostname,
                        "prefix": prefix,
                        "protocol": protocol,
                        "admin_distance": admin_distance,
                        "metric": metric
                    }

                    continue

                #
                # BGP/static/etc route where next-hop is present
                # on the same line.
                #
                if next_hop:

                    route = RouteEntry(
                        router=hostname,
                        vrf="global",
                        prefix=prefix,
                        next_hop=next_hop,
                        protocol=protocol,
                        metric=metric
                    )

                    if admin_distance is not None:
                        route.admin_distance = admin_distance

                    routes.append(route)

                continue

            #
            # ---------------------------------------------------------
            # 3. Continuation line
            #
            # is directly connected, <interface>
            # ---------------------------------------------------------
            #
            if (
                pending_connected
                and line.startswith(
                    "is directly connected,"
                )
            ):

                interface = line.split(
                    ",",
                    1
                )[1].strip()

                route = RouteEntry(
                    router=pending_connected["router"],
                    vrf="global",
                    prefix=pending_connected["prefix"],
                    next_hop=None,
                    protocol=pending_connected["protocol"],
                    exit_interface=interface,
                    metric=pending_connected["metric"]
                )

                if (
                    pending_connected[
                        "admin_distance"
                    ]
                    is not None
                ):
                    route.admin_distance = (
                        pending_connected[
                            "admin_distance"
                        ]
                    )

                routes.append(route)

                pending_connected = None

                continue

            #
            # ---------------------------------------------------------
            # 4. Continuation line with next-hop
            #
            # [20/50] via 100.72.33.13, 7w0d
            # ---------------------------------------------------------
            #
            if pending_connected:

                continuation = re.match(
                    r"^\[(?P<distance>\d+)/(?P<metric>\d+)\]"
                    r"\s+via\s+"
                    r"(?P<next_hop>\d+\.\d+\.\d+\.\d+)",
                    line
                )

                if continuation:

                    route = RouteEntry(
                        router=pending_connected["router"],
                        vrf="global",
                        prefix=pending_connected["prefix"],
                        next_hop=continuation.group(
                            "next_hop"
                        ),
                        protocol=pending_connected[
                            "protocol"
                        ],
                        metric=int(
                            continuation.group(
                                "metric"
                            )
                        )
                    )

                    route.admin_distance = int(
                        continuation.group(
                            "distance"
                        )
                    )

                    routes.append(route)

                    pending_connected = None

        return routes

    def _to_prefix(
        self,
        network,
        mask
    ):

        return str(
            ipaddress.ip_network(
                f"{network}/{mask}",
                strict=False
            )
        )

    def _protocol_from_code(
        self,
        code
    ):

        normalized = code.replace("*", "")

        mapping = {
            "B": "bgp",
            "C": "connected",
            "L": "local",
            "S": "static",
            "O": "ospf",
            "IA": "ospf",
            "E1": "ospf",
            "E2": "ospf",
            "N1": "ospf",
            "N2": "ospf",
            "R": "rip",
            "D": "eigrp",
            "EX": "eigrp",
            "i": "isis",
            "L1": "isis",
            "L2": "isis"
        }

        return mapping.get(
            normalized,
            normalized.lower()
        )