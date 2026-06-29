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

        #
        # Section
        #

        if "after-auto" in parts:
            rule.section = "after-auto"
        elif "before-auto" in parts:
            rule.section = "before-auto"
        else:
            rule.section = "manual"

        #
        # Source
        #

        if "source" in parts:

            i = parts.index("source")

            if len(parts) > i + 3:

                if parts[i + 1] == "static":

                    rule.source_original = parts[i + 2]
                    rule.source_translated = parts[i + 3]

                    rule.reason = "Static source NAT"

                elif parts[i + 1] == "dynamic":

                    rule.source_original = parts[i + 2]
                    rule.source_translated = parts[i + 3]

                    rule.reason = "Dynamic source NAT"

        #
        # Destination
        #

        if "destination" in parts:

            i = parts.index("destination")

            if len(parts) > i + 3:

                if parts[i + 1] == "static":

                    rule.destination_original = parts[i + 2]
                    rule.destination_translated = parts[i + 3]

                    if rule.reason:
                        rule.reason += " + destination"

                    else:
                        rule.reason = "Static destination NAT"

        #
        # Service
        #

        if "service" in parts:

            i = parts.index("service")

            if len(parts) > i + 2:

                rule.service_original = parts[i + 1]
                rule.service_translated = parts[i + 2]

        return rule