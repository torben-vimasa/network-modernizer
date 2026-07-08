import json
from pathlib import Path

from parsers.firewall_route_parser import FirewallRouteParser


class FirewallRouteExportBuilder:

    def __init__(
        self,
        input_dir=Path("data/contexts"),
        output_file=Path("output/firewall_routes.json")
    ):
        self.input_dir = Path(input_dir)
        self.output_file = Path(output_file)
        self.parser = FirewallRouteParser()

    def build(self):

        all_routes = []

        for file in sorted(self.input_dir.glob("*.txt")):

            routes = self.parser.parse(
                file.read_text(
                    encoding="utf-8",
                    errors="ignore"
                ).splitlines()
            )

            for r in routes:
                r.router = file.stem
                r.vrf = file.stem

            all_routes.extend(routes)

        rows = []

        for r in all_routes:
            rows.append(
                {
                    "router": r.router,
                    "vrf": r.vrf,
                    "context": r.vrf,
                    "prefix": r.prefix,
                    "next_hop": r.next_hop,
                    "protocol": r.protocol,
                    "interface": getattr(r, "interface", None),
                    "egress_interface": getattr(r, "egress_interface", None),
                    "ingress_interface": getattr(r, "ingress_interface", None)
                }
            )

        self.output_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with open(self.output_file, "w", encoding="utf-8") as f:
            json.dump(
                rows,
                f,
                indent=4
            )

        return all_routes