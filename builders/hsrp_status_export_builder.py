import json
from dataclasses import asdict
from pathlib import Path

from parsers.hsrp_parser import HSRPParser


class HSRPStatusExportBuilder:

    def __init__(
        self,
        input_dir=Path("data/router_raw_clean"),
        output_file=Path("output/hsrp_status.json")
    ):
        self.input_dir = Path(input_dir)
        self.output_file = Path(output_file)
        self.parser = HSRPParser()

    def build(self):

        all_states = []

        for file in sorted(self.input_dir.glob("*.txt")):
            device = file.stem

            states = self.parser.parse(
                file.read_text(
                    encoding="utf-8",
                    errors="ignore"
                ).splitlines(),
                device=device
            )

            all_states.extend(states)

        self.output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(self.output_file, "w", encoding="utf-8") as f:
            json.dump(
                [asdict(s) for s in all_states],
                f,
                indent=4
            )

        return all_states