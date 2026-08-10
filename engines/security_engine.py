import ipaddress

from graph.graph import KnowledgeGraph
from models.acl_match import ACLMatch
from models.security_result import SecurityResult
from models.security_context import SecurityContext
from models.security_assessment import SecurityAssessment


class SecurityEngine:

    def __init__(self, graph: KnowledgeGraph):
        self.graph = graph

    def is_permitted(
        self,
        source,
        destination,
        protocol=None,
        service=None,
        context=None,
        ingress_interface=None
    ):
        result = SecurityResult()

        rules = self._matching_rules(
            source,
            destination,
            protocol,
            service
        )

        if context or ingress_interface:
            rules = [
                rule
                for rule in rules
                if self._rule_applies_to_interface(
                    rule,
                    context,
                    ingress_interface
                )
            ]

        for rule in rules:
            if rule.properties.get("action") == "deny":
                result.permitted = False
                result.rule = rule
                result.match = self._build_acl_match(rule)
                result.reason = f"Matched deny rule {rule.name}"
                return result

        for rule in rules:
            if rule.properties.get("action") == "permit":
                result.permitted = True
                result.rule = rule
                result.match = self._build_acl_match(rule)
                result.reason = f"Matched permit rule {rule.name}"
                return result

        result.permitted = False
        result.reason = "No ACL rule matched"
        return result
        
    def _build_acl_match(self, rule):
        acl_name = rule.properties.get("acl")
        acl_node = self.graph.find("ACL", acl_name)

        context = None
        interface = None
        firewall = None

        if acl_node:
            for relation, neighbor in self.graph.neighbors(acl_node.id):
                if relation == "USES_ACL" and neighbor.type == "ASAInterface":
                    interface = neighbor.properties.get("interface")

                    for rel2, ctx in self.graph.neighbors(neighbor.id):
                        if rel2 == "HAS_INTERFACE" and ctx.type == "Context":
                            context = ctx.name

                    if context:
                        for rel3, fw in self.graph.neighbors(ctx.id):
                            if rel3 == "HAS_CONTEXT" and fw.type == "Firewall":
                                firewall = fw.name

        return ACLMatch(
            firewall=firewall,
            context=context,
            interface=interface,
            acl=acl_name,
            rule=rule.properties.get("sequence"),
            action=rule.properties.get("action"),
            raw=rule.properties.get("raw")
        )

    def _matching_rules(self, source, destination, protocol, service):
        matches = []

        for rule in self.graph.nodes.values():
            if rule.type != "ACLRule":
                continue

            if not self._protocol_matches(rule, protocol):
                continue

            if not self._service_matches(rule, service):
                continue

            source_targets = self._targets(rule.id, "USES_SOURCE")
            destination_targets = self._targets(rule.id, "USES_DESTINATION")

            if not source_targets or not destination_targets:
                continue

            source_match = any(
                self._node_matches_value(target, source)
                for target in source_targets
            )

            destination_match = any(
                self._node_matches_value(target, destination)
                for target in destination_targets
            )

            if source_match and destination_match:
                matches.append(rule)

        return matches

    def _protocol_matches(self, rule, protocol):
        if not protocol:
            return True

        rule_protocol = str(
            rule.properties.get("protocol") or ""
        ).lower()

        requested_protocol = str(protocol).lower()

        if rule_protocol == "object-group":
            return bool(
                rule.properties.get("service")
            )

        if rule_protocol in ["ip", "any"]:
            return True

        return rule_protocol == requested_protocol

    def _service_matches(self, rule, service):
        if not service:
            return True

        return rule.properties.get("service") == service

    def _targets(self, node_id, relationship_type):
        return [
            neighbor
            for relation, neighbor in self.graph.neighbors(node_id)
            if relation == relationship_type
        ]

    def _node_matches_value(self, node, value):
        if node.type == "NetworkObject":
            return self._network_object_matches(node, value)

        if node.type == "ObjectGroup":
            return self._object_group_matches(node, value)

        return False

    def _network_object_matches(self, node, value):
        if node.name == "any":
            return True

        object_value = node.properties.get("value")

        if object_value == value:
            return True

        if object_value == f"host {value}":
            return True

        if node.name == value:
            return True

        if node.name == f"host {value}":
            return True

        if node.name.endswith(f"_{value}"):
            return True

        if node.name.endswith(f":{value}"):
            return True

        if node.name.endswith(f":host {value}"):
            return True

        if node.properties.get("type") == "network":
            try:
                return ipaddress.ip_address(value) in ipaddress.ip_network(
                    object_value,
                    strict=False
                )
            except (TypeError, ValueError):
                return False

        return False

    def _object_group_matches(self, node, value):
        for relation, member in self.graph.neighbors(node.id):
            if relation != "HAS_MEMBER":
                continue

            if self._node_matches_value(member, value):
                return True

        return False

    def _rule_applies_to_interface(
        self,
        rule,
        context,
        ingress_interface
    ):
        acl_name = rule.properties.get("acl")

        if not acl_name:
            return False

        for node in self.graph.nodes.values():
            if node.type != "ASAInterface":
                continue

            if node.properties.get("context") != context:
                continue

            interface_matches = (
                node.properties.get("nameif") == ingress_interface
                or node.properties.get("interface") == ingress_interface
            )

            if not interface_matches:
                continue

            for relation, neighbor in self.graph.neighbors(node.id):
                if (
                    relation == "USES_ACL"
                    and neighbor.type == "ACL"
                    and neighbor.name == acl_name
                ):
                    return True

        return False

    def evaluate_context(
        self,
        security_context: SecurityContext
    ):
        if security_context.inventory_boundary:
            return self._evaluate_inventory_boundary(
                security_context
            )

        return SecurityAssessment(
            classification="unclassified",
            disposition="observe",
            confidence="low",
            message="No context-aware security classification matched."
        )

    def _evaluate_inventory_boundary(
        self,
        security_context: SecurityContext
    ):
        evidence = []

        if security_context.firewall_traversed:
            evidence.append("firewall_traversed")

        if security_context.acl_permitted is True:
            evidence.append("acl_permitted")

        if security_context.nat_evaluated:
            evidence.append("nat_evaluated")

        if security_context.forwarding_complete:
            evidence.append("forwarding_complete")

        if security_context.egress_interface:
            evidence.append(
                f"egress_interface={security_context.egress_interface}"
            )

        if security_context.next_hop:
            evidence.append(
                f"next_hop={security_context.next_hop}"
            )

        if (
            security_context.forwarding_complete
            and security_context.egress_device
            and security_context.egress_interface
        ):
            return SecurityAssessment(
                classification="permitted_to_inventory_boundary",
                disposition="observe",
                confidence="high",
                message=(
                    "Traffic is permitted through the managed security path "
                    "and exits the known inventory."
                ),
                device=security_context.egress_device,
                interface=security_context.egress_interface,
                next_hop=security_context.next_hop,
                evidence=evidence
            )

        return SecurityAssessment(
            classification="inventory_boundary_unresolved",
            disposition="observe",
            confidence="medium",
            message=(
                "Trace reached the inventory boundary, but managed-path "
                "forwarding could not be fully established."
            ),
            device=security_context.egress_device,
            interface=security_context.egress_interface,
            next_hop=security_context.next_hop,
            evidence=evidence
        )
