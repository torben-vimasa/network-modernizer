import ipaddress

from graph.graph import KnowledgeGraph
from models.acl_match import ACLMatch
from models.security_result import SecurityResult


class SecurityEngine:

    def __init__(self, graph: KnowledgeGraph):
        self.graph = graph

    def is_permitted(self, source, destination, protocol=None, service=None):
        result = SecurityResult()
        matches = self._matching_rules(source, destination, protocol, service)

        for rule in matches:
            if rule.properties.get("action") == "deny":
                result.permitted = False
                result.rule = rule
                result.match = self._build_acl_match(rule)
                result.reason = f"Matched deny rule {rule.name}"
                return result

        for rule in matches:
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

        context = rule.properties.get("context")
        interface = rule.properties.get("asa_interface")
        firewall = context

        if acl_node:
            for relation, neighbor in self.graph.neighbors(acl_node.id):
                if relation == "USES_ACL" and neighbor.type == "ASAInterface":
                    interface = (
                        neighbor.properties.get("nameif")
                        or neighbor.properties.get("interface")
                        or interface
                    )

                    for rel2, ctx in self.graph.neighbors(neighbor.id):
                        if rel2 == "HAS_INTERFACE" and ctx.type == "Context":
                            context = ctx.name
                            for rel3, fw in self.graph.neighbors(ctx.id):
                                if rel3 == "HAS_CONTEXT" and fw.type == "Firewall":
                                    firewall = fw.name

        return ACLMatch(
            firewall=firewall,
            context=context,
            interface=interface,
            acl=acl_name,
            rule=(
                rule.properties.get("line_number")
                or rule.properties.get("sequence")
            ),
            action=rule.properties.get("action"),
            raw=rule.properties.get("raw")
        )

    def _matching_rules(self, source, destination, protocol, service):
        matches = []

        for rule in self.graph.find_by_type("ACLRule"):
            if not self._protocol_matches(rule, protocol):
                continue

            if not self._service_matches(rule, service):
                continue

            source_targets = self._targets(rule.id, "USES_SOURCE")
            destination_targets = self._targets(rule.id, "USES_DESTINATION")

            source_match = (
                any(
                    self._node_matches_value(target, source)
                    for target in source_targets
                )
                if source_targets
                else self._endpoint_property_matches(
                    rule.properties.get("source_type"),
                    rule.properties.get("source_value"),
                    source
                )
            )

            destination_match = (
                any(
                    self._node_matches_value(target, destination)
                    for target in destination_targets
                )
                if destination_targets
                else self._endpoint_property_matches(
                    rule.properties.get("destination_type"),
                    rule.properties.get("destination_value"),
                    destination
                )
            )

            if source_match and destination_match:
                matches.append(rule)

        return matches

    def _protocol_matches(self, rule, protocol):
        if not protocol:
            return True

        rule_protocol = str(rule.properties.get("protocol") or "").lower()
        requested_protocol = str(protocol).lower()

        if rule_protocol in ["ip", "any"]:
            return True

        if rule_protocol in ["object-group", "object"]:
            return bool(rule.properties.get("service"))

        return rule_protocol == requested_protocol

    def _service_matches(self, rule, service):
        if not service:
            return True

        rule_service = str(rule.properties.get("service") or "").lower()
        requested_service = str(service).lower()

        if not rule_service:
            return True

        return rule_service == requested_service

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

    def _endpoint_property_matches(self, endpoint_type, endpoint_value, value):
        if not endpoint_type or not endpoint_value:
            return False

        endpoint_type = str(endpoint_type).lower()

        if endpoint_type == "any":
            return True

        if endpoint_type == "host":
            return str(endpoint_value) == str(value)

        if endpoint_type == "network":
            return self._ip_in_network(value, endpoint_value)

        return self._raw_value_matches(endpoint_value, value)

    def _network_object_matches(self, node, value):
        if node.name in ["any", "any4", "any6"]:
            return True

        candidates = [
            node.properties.get("value"),
            node.name,
            node.name.rsplit(":", 1)[-1]
        ]

        return any(
            self._raw_value_matches(candidate, value)
            for candidate in candidates
            if candidate
        )

    def _raw_value_matches(self, candidate, value):
        candidate = str(candidate).strip()
        value = str(value).strip()

        if candidate in ["any", "any4", "any6"]:
            return True

        if candidate == value or candidate == f"host {value}":
            return True

        if candidate.endswith(f"_{value}"):
            return True

        if candidate.endswith(f":{value}"):
            return True

        if candidate.endswith(f":host {value}"):
            return True

        if "/" in candidate:
            return self._ip_in_network(value, candidate)

        parts = candidate.split()
        if len(parts) == 2:
            try:
                network = ipaddress.ip_network(
                    f"{parts[0]}/{parts[1]}",
                    strict=False
                )
            except ValueError:
                pass
            else:
                return self._ip_in_network(value, str(network))

        return False

    def _ip_in_network(self, value, network):
        try:
            address = ipaddress.ip_address(value)
            subnet = ipaddress.ip_network(network, strict=False)
        except ValueError:
            return False

        return address in subnet

    def _object_group_matches(self, node, value):
        for relation, member in self.graph.neighbors(node.id):
            if relation != "HAS_MEMBER":
                continue

            if self._node_matches_value(member, value):
                return True

        return False
