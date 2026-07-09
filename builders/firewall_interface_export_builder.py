import json
from dataclasses import asdict
from pathlib import Path

from parsers.firewall_interface_parser import FirewallInterfaceParser


class FirewallInterfaceExportBuilder:

    def __init__(
        self,
        input_dir=Path("data/firewalls"),
        output_file=Path("output/firewall_interfaces.json")
    ):
        self.input_dir = Path(input_dir)
        self.output_file = Path(output_file)
        self.parser = FirewallInterfaceParser()

    def build(self):

        all_interfaces = []

        for file in sorted(self.input_dir.glob("*.txt")):
            with open(file, encoding="utf-8", errors="ignore") as f:
                interfaces = self.parser.parse(f.readlines())

            all_interfaces.extend(interfaces)

        self.output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(self.output_file, "w", encoding="utf-8") as f:
            json.dump(
                [asdict(interface) for interface in all_interfaces],
                f,
                indent=4
            )

        return all_interfaces