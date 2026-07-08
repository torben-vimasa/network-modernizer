import json
from dataclasses import asdict
from pathlib import Path

from parsers.route_parser import RouteParser


class RouterRouteTableExportBuilder:

    def __init__(
        self,
        input_dir=Path("data/router_routes"),
        output_file=Path("output/routes_runtime.json")
    ):
        self.input_dir = Path(input_dir)
        self.output_file = Path(output_file)
        self.parser = RouteParser()

    def build(self):
        all_routes = []

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

        self.output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(self.output_file, "w", encoding="utf-8") as f:
            json.dump(
                [asdict(r) for r in all_routes],
                f,
                indent=4
            )

        return all_routes