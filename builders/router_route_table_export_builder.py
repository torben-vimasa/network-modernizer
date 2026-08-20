import json

from dataclasses import asdict
from pathlib import Path

from models.route_entry import RouteEntry
from parsers.route_parser import RouteParser
from parsers.router_inventory_parser import RouterInventoryParser


class RouterRouteTableExportBuilder:

    def __init__(
        self,
        input_dir=Path("data/router_routes"),
        router_raw_dir=Path("data/router_raw"),
        output_file=Path("output/routes_runtime.json")
    ):
        self.input_dir = Path(input_dir)
        self.router_raw_dir = Path(router_raw_dir)
        self.output_file = Path(output_file)

        self.parser = RouteParser()
        self.inventory_parser = RouterInventoryParser()

    def build(self):

        all_routes = []

        #
        # Runtime / operational route tables
        #
        if self.input_dir.exists():

            for file in sorted(self.input_dir.glob("*")):

                if not file.is_file():
                    continue

                routes = self.parser.parse_route_table(
                    router_name=file.stem,
                    lines=file.read_text(
                        encoding="utf-8",
                        errors="ignore"
                    ).splitlines()
                )

                all_routes.extend(routes)

        #
        # Runtime / operational route tables stored
        # together with raw router inventory.
        #
        # Example:
        #
        # data/router_raw/OBvDCR1/
        #   OBvDCR1 - show ip route vrf bane1.txt
        #
        if self.router_raw_dir.exists():

            for file in sorted(
                self.router_raw_dir.rglob(
                    "*show ip route*.txt"
                )
            ):

                if not file.is_file():
                    continue

                router_name = file.parent.name

                routes = self.parser.parse_route_table(
                    router_name=router_name,
                    lines=file.read_text(
                        encoding="utf-8",
                        errors="ignore"
                    ).splitlines()
                )

                all_routes.extend(routes)

        #
        # Connected routes derived from router L3 interfaces
        #
        if self.router_raw_dir.exists():

            for file in sorted(
                self.router_raw_dir.rglob(
                    "*section interface*.txt"
                )
            ):

                lines = file.read_text(
                    encoding="utf-8",
                    errors="ignore"
                ).splitlines()

                router = self.inventory_parser.parse(
                    file.parent.name,
                    lines
                )

                for interface in router.interfaces:

                    if not interface.ip or not interface.prefix:
                        continue

                    all_routes.append(
                        RouteEntry(
                            router=router.name,
                            vrf=interface.vrf,
                            prefix=interface.prefix,

                            #
                            # Current TraceWorkflow recognizes a
                            # directly connected destination when
                            # route next-hop matches a local
                            # RouterInterface IP.
                            #
                            next_hop=interface.ip,

                            protocol="connected",
                            exit_interface=interface.name,
                            metric=0
                        )
                    )

        #
        # Remove exact duplicates
        #
        unique = {}

        for route in all_routes:

            key = (
                route.router,
                route.vrf,
                route.prefix,
                route.next_hop,
                route.protocol
            )

            unique[key] = route

        all_routes = list(unique.values())

        self.output_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with open(
            self.output_file,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                [
                    asdict(route)
                    for route in all_routes
                ],
                f,
                indent=4
            )

        return all_routes