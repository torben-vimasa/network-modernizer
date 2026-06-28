from models.nat_rule import NATRule


class ASANATParser:

    def parse_line(self, line):

        line = line.strip()

        if not line.startswith("nat "):
            return None

        return NATRule(
            raw=line
        )