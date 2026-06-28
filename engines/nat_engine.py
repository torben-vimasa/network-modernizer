from models.nat_result import NATResult


class NATEngine:

    def __init__(self, rules=None):
        self.rules = rules or []

    def translate(self, packet):

        for rule in self.rules:

            if self._matches_source(rule, packet.source) and self._matches_destination(rule, packet.destination):

                source_after = rule.source_translated or packet.source
                destination_after = rule.destination_translated or packet.destination

                return NATResult(
                    matched=True,
                    rule=rule,
                    source_before=packet.source,
                    source_after=source_after,
                    destination_before=packet.destination,
                    destination_after=destination_after,
                    reason="Matched NAT rule"
                )

        return NATResult(
            matched=False,
            rule=None,
            source_before=packet.source,
            source_after=packet.source,
            destination_before=packet.destination,
            destination_after=packet.destination,
            reason="No NAT rule matched"
        )

    def _matches_source(self, rule, source):

        if not rule.source_original:
            return True

        return rule.source_original == source

    def _matches_destination(self, rule, destination):

        if not rule.destination_original:
            return True

        return rule.destination_original == destination