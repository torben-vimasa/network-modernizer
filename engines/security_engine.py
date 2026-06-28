from graph.graph import KnowledgeGraph
from models.acl_match import ACLMatch
from models.security_result import SecurityResult


class SecurityEngine:

    def __init__(self, graph: KnowledgeGraph):
        self.graph = graph

    def is_permitted(self, source, destination, protocol=None, service=None):
        result = SecurityResult()

        for rule in self._matching_rules(source, destination, protocol, service):
            if rule.properties.get("action") == "deny":
                result.permitted = False
                result.rule = rule
                result.match = self._build_acl_match(rule)
                result.reason = f"Matched deny rule {rule.name}"
                return result

        for rule in self._matching_rules(source, destination, protocol, service):
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

        return rule.properties.get("protocol") == protocol

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

        return False

    def _object_group_matches(self, node, value):
        for relation, member in self.graph.neighbors(node.id):
            if relation != "HAS_MEMBER":
                continue

            if self._node_matches_value(member, value):
                return True

        return False