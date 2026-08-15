from copy import deepcopy

from models.confidence import Confidence
from models.nat_explanation import NATExplanation
from models.nat_result import NATResult


class NATEngine:

    def __init__(self, rules=None, graph=None):
        self.rules = self._sort_rules(rules or [])
        self.graph = graph

    def translate(
        self,
        packet,
        context=None,
        ingress_interface=None,
        egress_interface=None
    ):

        translated = deepcopy(packet)

        for rule in self.rules:
            if context and rule.context and rule.context != context:
                continue

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
        return self._matches_value(
            rule.source_original,
            source
        )

    def _matches_destination(self, rule, destination):
        return self._matches_value(
            rule.destination_original,
            destination
        )

    def _matches_value(self, configured_value, packet_value):
        if not configured_value:
            return True

        if configured_value in ["any", "any4"]:
            return True

        if configured_value == packet_value:
            return True

        if not self.graph:
            return False

        node = (
            self.graph.find("NetworkObject", configured_value)
            or self.graph.find("ObjectGroup", configured_value)
        )

        if not node:
            return False

        return self._node_matches_ip(
            node,
            packet_value,
            visited=set()
        )

    def _node_matches_ip(self, node, ip_value, visited):
        import ipaddress

        if node.id in visited:
            return False

        visited.add(node.id)

        if node.type == "ObjectGroup":
            for relation, member in self.graph.neighbors(node.id):
                if relation != "HAS_MEMBER":
                    continue

                if self._node_matches_ip(
                    member,
                    ip_value,
                    visited
                ):
                    return True

            return False

        value = node.properties.get("value")

        if not value:
            value = node.name

        value = str(value).strip()

        if value.startswith("host "):
            return value.split(maxsplit=1)[1] == ip_value

        if value == ip_value:
            return True

        try:
            return ipaddress.ip_address(ip_value) in ipaddress.ip_network(
                value,
                strict=False
            )
        except ValueError:
            return False