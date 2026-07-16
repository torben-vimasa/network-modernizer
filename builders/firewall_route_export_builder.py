import ipaddress
import json
from pathlib import Path

from models.route_entry import RouteEntry
from parsers.firewall_interface_parser import FirewallInterfaceParser
from parsers.firewall_route_parser import FirewallRouteParser


class FirewallRouteExportBuilder:

    def __init__(
        self,
        input_dir=Path("data/contexts"),
        output_file=Path("output/firewall_routes.json")
    ):
        self.input_dir = Path(input_dir)
        self.output_file = Path(output_file)
        self.route_parser = FirewallRouteParser()
        self.interface_parser = FirewallInterfaceParser()

    def build(self):

        all_routes = []

        for file in sorted(self.input_dir.glob("*.txt")):

            lines = file.read_text(
                encoding="utf-8",
                errors="ignore"
            ).splitlines()

            context = file.stem

            #
            # Configured routes
            #
            routes = self.route_parser.parse(lines)

            for route in routes:
                route.router = context
                route.vrf = context

            all_routes.extend(routes)

            #
            # Connected routes derived from L3 interfaces
            #
            interfaces = self.interface_parser.parse(lines)

            for interface in interfaces:

                if not interface.ip or not interface.mask:
                    continue

                try:
                    network = ipaddress.ip_network(
                        f"{interface.ip}/{interface.mask}",
                        strict=False
                    )
                except ValueError:
                    continue

                connected_route = RouteEntry(
                    router=context,
                    vrf=context,
                    prefix=str(network),
                    next_hop=None,
                    protocol="connected"
                )

                connected_route.interface = interface.interface
                connected_route.egress_interface = (
                    interface.nameif or interface.interface
                )
                connected_route.ingress_interface = None

                all_routes.append(connected_route)

        rows = []

        for route in all_routes:
            rows.append(
                {
                    "router": route.router,
                    "vrf": route.vrf,
                    "context": route.vrf,
                    "prefix": route.prefix,
                    "next_hop": route.next_hop,
                    "protocol": route.protocol,
                    "interface": getattr(route, "interface", None),
                    "egress_interface": getattr(
                        route,
                        "egress_interface",
                        None
                    ),
                    "ingress_interface": getattr(
                        route,
                        "ingress_interface",
                        None
                    )
                }
            )

        self.output_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with open(
            self.output_file,
            "w",
            encoding="utf-8"
        ) as handle:
            json.dump(
                rows,
                handle,
                indent=4
            )

        return all_routes