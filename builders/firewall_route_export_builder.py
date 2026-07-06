import json
from pathlib import Path

from parsers.firewall_route_parser import FirewallRouteParser


class FirewallRouteExportBuilder:

    def __init__(
        self,
        input_file=Path("data/BDK-Mgmt show route.txt"),
        output_file=Path("output/firewall_routes.json")
    ):
        self.input_file = Path(input_file)
        self.output_file = Path(output_file)
        self.parser = FirewallRouteParser()

    def build(self):

        with open(self.input_file, encoding="utf-8", errors="ignore") as f:
            routes = self.parser.parse(f.readlines())

        rows = []

        for r in routes:
            rows.append(
                {
                    "router": r.router,
                    "vrf": r.vrf,
                    "context": r.vrf,
                    "prefix": r.prefix,
                    "next_hop": r.next_hop,
                    "protocol": r.protocol,
                    "interface": getattr(r, "interface", None),
                    "egress_interface": getattr(r, "egress_interface", None)
                }
            )

        self.output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(self.output_file, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=4)

        return routes