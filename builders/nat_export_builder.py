import json
from dataclasses import asdict
from pathlib import Path

from parsers.asa_nat_parser import ASANATParser
from utils.firewall_context import detect_firewall_context


class NATExportBuilder:

    def __init__(
        self,
        output_file=Path("output/nat_rules.json")
    ):
        self.output_file = Path(output_file)
        self.parser = ASANATParser()

    def build(self):

        input_dirs = [
            Path("data/contexts"),
            Path("data/firewalls")
        ]

        input_files = []

        for input_dir in input_dirs:

            if not input_dir.exists():
                continue

            input_files.extend(
                sorted(input_dir.glob("*.txt"))
            )

        #
        # Avoid duplicate contexts.
        #
        # If the same context exists in both directories,
        # data/contexts is preferred.
        #
        files_by_context = {}

        for file in input_files:

            context = detect_firewall_context(file)

            if context not in files_by_context:
                files_by_context[context] = file
                continue

            if "contexts" in file.parts:
                files_by_context[context] = file

        rules = []

        for context, file in sorted(
            files_by_context.items()
        ):

            with open(
                file,
                encoding="utf-8",
                errors="ignore"
            ) as handle:
                parsed_rules = self.parser.parse_lines(
                    handle.readlines()
                )

            for rule in parsed_rules:
                rule.context = context
                rules.append(rule)

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
                [
                    asdict(rule)
                    for rule in rules
                ],
                handle,
                indent=4
            )

        return rules


if __name__ == "__main__":

    builder = NATExportBuilder()
    rules = builder.build()

    print()
    print("NAT Export Builder")
    print("=" * 60)
    print(f"Rules : {len(rules)}")
    print(f"Output: {builder.output_file}")