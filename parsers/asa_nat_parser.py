from models.nat_rule import NATRule


class ASANATParser:

    def parse_line(self, line):

        line = line.strip()

        if not line.startswith("nat "):
            return None

        parts = line.split()

        rule = NATRule(
            direction=parts[1].strip("()"),
            raw=line
        )

        #
        # Section
        #

        if "before-auto" in parts:
            rule.section = "before-auto"
        elif "after-auto" in parts:
            rule.section = "after-auto"
        else:
            rule.section = "manual"

        #
        # Source
        #

        if "source" in parts:

            i = parts.index("source")

            nat_type = parts[i + 1]

            rule.source_original = parts[i + 2]
            rule.source_translated = parts[i + 3]

            if nat_type == "static":
                rule.reason = "Static source NAT"
            else:
                rule.reason = "Dynamic source NAT"

        #
        # Destination
        #

        if "destination" in parts:

            i = parts.index("destination")

            nat_type = parts[i + 1]

            rule.destination_original = parts[i + 2]
            rule.destination_translated = parts[i + 3]

            if rule.reason:
                rule.reason += " + destination"

            else:
                if nat_type == "static":
                    rule.reason = "Static destination NAT"
                else:
                    rule.reason = "Dynamic destination NAT"

        #
        # Service
        #

        if "service" in parts:

            i = parts.index("service")

            rule.service_original = parts[i + 1]
            rule.service_translated = parts[i + 2]

        #
        # Detect Twice NAT
        #

        if (
            rule.source_original
            and
            rule.destination_original
        ):
            rule.reason = "Twice NAT"

        return rule