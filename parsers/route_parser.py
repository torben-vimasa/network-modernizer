import re

from models.route_entry import RouteEntry


class RouteParser:

    def parse_router_config(
        self,
        router_name,
        lines
    ):

        routes = []
        current_vrf = "default"

        for raw_line in lines:

            line = raw_line.strip()

            if not line:
                continue

            if line.startswith(
                "hostname "
            ):

                router_name = (
                    line.replace(
                        "hostname ",
                        ""
                    ).strip()
                )

                continue

            if line.startswith(
                "vrf context "
            ):

                current_vrf = (
                    line.replace(
                        "vrf context ",
                        ""
                    ).strip()
                )

                continue

            if line.startswith(
                "interface "
            ):

                current_vrf = (
                    "default"
                )

                continue

            route = (
                self._parse_static_route(
                    router_name,
                    current_vrf,
                    line
                )
            )

            if route:
                routes.append(
                    route
                )

        return routes


    def _parse_static_route(
        self,
        router_name,
        vrf,
        line
    ):

        match = re.match(
            r"^ip route\s+"
            r"(\S+)\s+"
            r"(\S+)",
            line
        )

        if not match:
            return None

        prefix = (
            match.group(1)
        )

        next_hop = (
            match.group(2)
        )

        return RouteEntry(
            router=router_name,
            vrf=vrf,
            prefix=prefix,
            next_hop=next_hop,
            protocol="static"
        )


    def parse_route_table(
        self,
        router_name,
        lines
    ):

        #
        # Support both:
        #
        #   NX-OS route-table format
        #   IOS XR show ip route format
        #
        routes = []

        routes.extend(
            self._parse_nxos_route_table(
                router_name,
                lines
            )
        )

        routes.extend(
            self._parse_iosxr_route_table(
                router_name,
                lines
            )
        )

        #
        # Remove exact duplicates.
        #
        unique = {}

        for route in routes:

            key = (
                route.router,
                route.vrf,
                route.prefix,
                route.next_hop,
                route.protocol
            )

            unique[key] = route

        return list(
            unique.values()
        )


    def _parse_nxos_route_table(
        self,
        router_name,
        lines
    ):

        routes = []

        current_vrf = None
        current_prefix = None

        for raw_line in lines:

            line = raw_line.strip()

            if not line:
                continue

            vrf_match = re.match(
                r'^IP Route Table for VRF '
                r'"(.+)"',
                line
            )

            if vrf_match:

                current_vrf = (
                    vrf_match.group(1)
                )

                current_prefix = None

                continue

            prefix_match = re.match(
                r"^"
                r"(\d+\.\d+\.\d+\.\d+/\d+)"
                r",",
                line
            )

            if prefix_match:

                current_prefix = (
                    prefix_match.group(1)
                )

                continue

            via_match = re.match(
                r"^\*?via\s+"
                r"(\d+\.\d+\.\d+\.\d+)"
                r".*"
                r"(bgp|static|direct|local|"
                r"isis|ospf)",
                line,
                re.IGNORECASE
            )

            if (
                current_vrf
                and current_prefix
                and via_match
            ):

                next_hop = (
                    via_match.group(1)
                )

                protocol = (
                    via_match.group(2)
                    .lower()
                )

                routes.append(
                    RouteEntry(
                        router=router_name,
                        vrf=current_vrf,
                        prefix=current_prefix,
                        next_hop=next_hop,
                        protocol=protocol
                    )
                )

                current_prefix = None

        return routes


    def _parse_iosxr_route_table(
        self,
        router_name,
        lines
    ):

        routes = []

        current_vrf = None

        #
        # Protocol mapping from IOS XR route
        # codes to normalized protocol names.
        #
        protocol_map = {
            "C": "connected",
            "S": "static",
            "R": "rip",
            "B": "bgp",
            "D": "eigrp",
            "EX": "eigrp",
            "O": "ospf",
            "IA": "ospf",
            "N1": "ospf",
            "N2": "ospf",
            "E1": "ospf",
            "E2": "ospf",
            "i": "isis",
            "L1": "isis",
            "L2": "isis",
            "ia": "isis",
            "L": "local"
        }

        for raw_line in lines:

            line = raw_line.strip()

            if not line:
                continue

            #
            # Example:
            #
            # RP/0/RSP0/CPU0:OBvDCR1#
            # show ip route vrf bane1
            #
            command_match = re.search(
                r"show\s+ip\s+route\s+vrf\s+"
                r"(\S+)",
                line,
                re.IGNORECASE
            )

            if command_match:

                current_vrf = (
                    command_match.group(1)
                )

                continue

            #
            # Other possible IOS/XR heading:
            #
            # Routing Table: bane1
            #
            table_match = re.match(
                r"^Routing Table:\s*(\S+)",
                line,
                re.IGNORECASE
            )

            if table_match:

                current_vrf = (
                    table_match.group(1)
                )

                continue

            if not current_vrf:
                continue

            #
            # Routes with an IP next-hop.
            #
            # Examples:
            #
            # S* 0.0.0.0/0 [1/0]
            #    via 172.27.2.100, 1y07w
            #
            # B 10.9.64.0/24 [200/0]
            #   via 172.17.11.239
            #   (nexthop in vrf default)
            #
            route_match = re.match(
                r"^"
                r"([A-Za-z0-9]+)"
                r"\*?"
                r"\s+"
                r"(\d+\.\d+\.\d+\.\d+/\d+)"
                r"\s+"
                r"\[(\d+)/(\d+)\]"
                r"\s+via\s+"
                r"(\d+\.\d+\.\d+\.\d+)",
                line
            )

            if route_match:

                code = (
                    route_match.group(1)
                )

                prefix = (
                    route_match.group(2)
                )

                admin_distance = int(
                    route_match.group(3)
                )

                metric = int(
                    route_match.group(4)
                )

                next_hop = (
                    route_match.group(5)
                )

                protocol = (
                    protocol_map.get(
                        code
                    )
                )

                if not protocol:
                    continue

                #
                # IOS XR tells us whether this BGP
                # route is effectively iBGP/MP-BGP
                # by administrative distance.
                #
                if protocol == "bgp":

                    if admin_distance == 200:
                        protocol = "ibgp"

                    elif admin_distance == 20:
                        protocol = "ebgp"

                routes.append(
                    RouteEntry(
                        router=router_name,
                        vrf=current_vrf,
                        prefix=prefix,
                        next_hop=next_hop,
                        protocol=protocol,
                        metric=metric
                    )
                )

                continue

            #
            # Connected/local routes.
            #
            # Typical IOS XR examples:
            #
            # C 172.27.2.0/24 is directly
            #   connected, Bundle-Ether...
            #
            # L 172.27.2.102/32 is directly
            #   connected, Bundle-Ether...
            #
            connected_match = re.match(
                r"^"
                r"(C|L)"
                r"\s+"
                r"(\d+\.\d+\.\d+\.\d+/\d+)"
                r"\s+is directly connected"
                r"(?:,\s*(\S+))?",
                line
            )

            if connected_match:

                code = (
                    connected_match.group(1)
                )

                prefix = (
                    connected_match.group(2)
                )

                interface = (
                    connected_match.group(3)
                )

                protocol = (
                    "connected"
                    if code == "C"
                    else "local"
                )

                routes.append(
                    RouteEntry(
                        router=router_name,
                        vrf=current_vrf,
                        prefix=prefix,
                        next_hop=None,
                        protocol=protocol,
                        exit_interface=interface,
                        metric=0
                    )
                )

        return routes