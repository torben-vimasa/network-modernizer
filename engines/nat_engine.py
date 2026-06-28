from copy import deepcopy

from models.nat_result import NATResult


class NATEngine:

    def __init__(self, rules=None):
        self.rules = rules or []

    def translate(self, packet):

        translated = deepcopy(packet)

        for rule in self.rules:

            if (
                self._matches_source(rule, translated.source)
                and
                self._matches_destination(rule, translated.destination)
            ):

                result = NATResult(
                    matched=True,
                    rule=rule,
                    source_before=translated.source,
                    source_after=rule.source_translated or translated.source,
                    destination_before=translated.destination,
                    destination_after=rule.destination_translated or translated.destination,
                    reason="Matched NAT rule"
                )

                translated.source = result.source_after
                translated.destination = result.destination_after

                return translated, result

        result = NATResult(
            matched=False,
            rule=None,
            source_before=translated.source,
            source_after=translated.source,
            destination_before=translated.destination,
            destination_after=translated.destination,
            reason="No NAT rule matched"
        )

        return translated, result

    def _matches_source(self, rule, source):

        if not rule.source_original:
            return True

        return rule.source_original == source

    def _matches_destination(self, rule, destination):

        if not rule.destination_original:
            return True

        return rule.destination_original == destination