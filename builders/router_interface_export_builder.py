import json
from dataclasses import asdict
from pathlib import Path

from parsers.router_interface_parser import RouterInterfaceParser


class RouterInterfaceExportBuilder:

    def __init__(
        self,
        input_dir=Path("data/router_raw_clean"),
        output_file=Path("output/router_interfaces.json")
    ):
        self.input_dir = Path(input_dir)
        self.output_file = Path(output_file)
        self.parser = RouterInterfaceParser()

    def build(self):

        all_interfaces = []

        for file in sorted(self.input_dir.glob("*.txt")):
            device = file.stem.split("-")[0]

            with open(file, encoding="utf-8", errors="ignore") as f:
                interfaces = self.parser.parse(
                    f.readlines(),
                    device=device
                )

            all_interfaces.extend(interfaces)

        self.output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(self.output_file, "w", encoding="utf-8") as f:
            json.dump(
                [asdict(i) for i in all_interfaces],
                f,
                indent=4
            )

        return all_interfaces