from models.nat_rule import NATRule


class ASANATParser:

    def parse_line(self, line):

        line = line.strip()

        if not line.startswith("nat "):
            return None

        parts = line.split()

        direction = parts[1].strip("()")

        rule = NATRule(
            direction=direction,
            raw=line
        )

        if "source" in parts:
            source_index = parts.index("source")

            if (
                len(parts) > source_index + 3
                and parts[source_index + 1] == "static"
            ):
                rule.source_original = parts[source_index + 2]
                rule.source_translated = parts[source_index + 3]
                rule.reason = "Static source NAT"

        if "destination" in parts:
            destination_index = parts.index("destination")

            if (
                len(parts) > destination_index + 3
                and parts[destination_index + 1] == "static"
            ):
                rule.destination_original = parts[destination_index + 2]
                rule.destination_translated = parts[destination_index + 3]

                if rule.reason:
                    rule.reason = "Static source and destination NAT"
                else:
                    rule.reason = "Static destination NAT"

        return rule