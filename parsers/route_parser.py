import re

from models.route_entry import RouteEntry


class RouteParser:

    def parse_router_config(self, router_name, lines):
        routes = []
        current_vrf = "default"

        for raw_line in lines:
            line = raw_line.strip()

            if not line:
                continue

            if line.startswith("hostname "):
                router_name = line.replace("hostname ", "").strip()
                continue

            if line.startswith("vrf context "):
                current_vrf = line.replace("vrf context ", "").strip()
                continue

            if line.startswith("interface "):
                current_vrf = "default"
                continue

            route = self._parse_static_route(router_name, current_vrf, line)

            if route:
                routes.append(route)

        return routes

    def _parse_static_route(self, router_name, vrf, line):
        match = re.match(
            r"^ip route\s+(\S+)\s+(\S+)",
            line
        )

        if not match:
            return None

        prefix = match.group(1)
        next_hop = match.group(2)

        return RouteEntry(
            router=router_name,
            vrf=vrf,
            prefix=prefix,
            next_hop=next_hop,
            protocol="static"
        )

    def parse_route_table(self, router_name, lines):
        routes = []
        current_vrf = None
        current_prefix = None

        for raw_line in lines:
            line = raw_line.strip()

            if not line:
                continue

            vrf_match = re.match(
                r'^IP Route Table for VRF "(.+)"',
                line
            )

            if vrf_match:
                current_vrf = vrf_match.group(1)
                current_prefix = None
                continue

            prefix_match = re.match(
                r"^(\d+\.\d+\.\d+\.\d+/\d+),",
                line
            )

            if prefix_match:
                current_prefix = prefix_match.group(1)
                continue

            via_match = re.match(
                r"^\*?via\s+(\d+\.\d+\.\d+\.\d+).*(bgp|static|direct|local|isis|ospf)",
                line
            )

            if current_vrf and current_prefix and via_match:
                next_hop = via_match.group(1)
                protocol = via_match.group(2)

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