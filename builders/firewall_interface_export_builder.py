import json
from dataclasses import asdict
from pathlib import Path

from parsers.firewall_interface_parser import FirewallInterfaceParser
from utils.firewall_context import detect_firewall_context


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

            context = detect_firewall_context(file)

            with open(
                file,
                encoding="utf-8",
                errors="ignore"
            ) as f:
                interfaces = self.parser.parse(
                    f.readlines()
                )

            for interface in interfaces:
                interface.context = context

            all_interfaces.extend(interfaces)

        self.output_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        rows = []

        for interface in all_interfaces:

            row = asdict(interface)

            row["context"] = (
                interface.context
                or interface.device
            )

            rows.append(row)

        with open(
            self.output_file,
            "w",
            encoding="utf-8"
        ) as f:
            json.dump(
                rows,
                f,
                indent=4
            )

        return all_interfaces


if __name__ == "__main__":

    builder = FirewallInterfaceExportBuilder()
    interfaces = builder.build()

    print()
    print("Firewall Interface Export Builder")
    print("=" * 60)
    print(f"Interfaces: {len(interfaces)}")
    print(f"Output    : {builder.output_file}")