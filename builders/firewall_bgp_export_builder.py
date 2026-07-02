import json
from dataclasses import asdict
from pathlib import Path

from parsers.firewall_bgp_parser import FirewallBGPParser


class FirewallBGPExportBuilder:

    def __init__(
        self,
        input_dir=Path("data/firewalls"),
        output_file=Path("output/firewall_bgp_neighbors.json")
    ):
        self.input_dir = Path(input_dir)
        self.output_file = Path(output_file)
        self.parser = FirewallBGPParser()

    def build(self):

        all_neighbors = []

        for file in sorted(self.input_dir.glob("*.txt")):
            with open(file, encoding="utf-8", errors="ignore") as f:
                neighbors = self.parser.parse(f.readlines())

            all_neighbors.extend(neighbors)

        self.output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(self.output_file, "w", encoding="utf-8") as f:
            json.dump(
                [asdict(n) for n in all_neighbors],
                f,
                indent=4
            )

        return all_neighbors