from models.nat_rule import NATRule


class ASANATParser:

    def parse_file(self, file_path):

        rules = []

        with open(file_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                rule = self.parse_line(line)

                if rule:
                    rules.append(rule)

        return rules

    def parse_line(self, line):

        line = line.strip()

        if not line.startswith("nat "):
            return None

        parts = line.split()

        rule = NATRule(
            direction=parts[1].strip("()"),
            raw=line
        )

        if "before-auto" in parts:
            rule.section = "before-auto"
        elif "after-auto" in parts:
            rule.section = "after-auto"
        else:
            rule.section = "manual"

        if "source" in parts:
            i = parts.index("source")
            nat_type = parts[i + 1]
            rule.source_original = parts[i + 2]
            rule.source_translated = parts[i + 3]
            rule.reason = "Static source NAT" if nat_type == "static" else "Dynamic source NAT"

        if "destination" in parts:
            i = parts.index("destination")
            rule.destination_original = parts[i + 2]
            rule.destination_translated = parts[i + 3]
            rule.reason = "Twice NAT" if rule.source_original else "Static destination NAT"

        if "service" in parts:
            i = parts.index("service")
            rule.service_original = parts[i + 1]
            rule.service_translated = parts[i + 2]

        if rule.source_original and rule.destination_original:
            rule.reason = "Twice NAT"

        return rule