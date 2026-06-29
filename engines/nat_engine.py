from copy import deepcopy

from models.confidence import Confidence
from models.nat_explanation import NATExplanation
from models.nat_result import NATResult


class NATEngine:

    def __init__(self, rules=None):
        self.rules = self._sort_rules(rules or [])

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

                result.explanation = NATExplanation(
                    matched=True,
                    reason=rule.reason or "Matched NAT rule",
                    source_before=result.source_before,
                    source_after=result.source_after,
                    destination_before=result.destination_before,
                    destination_after=result.destination_after,
                    rule_name=rule.name,
                    direction=rule.direction,
                    section=rule.section,
                    confidence=Confidence(
                        level="high",
                        score=1.0,
                        reason="Exact NAT rule match"
                    )
                )

                translated.source = result.source_after
                translated.destination = result.destination_after

                translated.add_history(
                    f"NAT: {result.source_before} -> {result.source_after}"
                )

                translated.add_history(
                    f"NAT destination: {result.destination_before} -> {result.destination_after}"
                )

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

        result.explanation = NATExplanation(
            matched=False,
            reason="No NAT rule matched",
            confidence=Confidence(
                level="high",
                score=1.0,
                reason="All configured NAT rules evaluated"
            )
        )

        return translated, result

    def _sort_rules(self, rules):

        section_order = {
            "before-auto": 1,
            "manual": 1,
            "auto": 2,
            "after-auto": 3
        }

        return sorted(
            rules,
            key=lambda rule: section_order.get(rule.section, 99)
        )

    def _matches_source(self, rule, source):

        if not rule.source_original:
            return True

        return rule.source_original == source

    def _matches_destination(self, rule, destination):

        if not rule.destination_original:
            return True

        return rule.destination_original == destination