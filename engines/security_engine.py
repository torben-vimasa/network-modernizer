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

        rules = sorted(
            rules,
            key=lambda rule: int(
                rule.properties.get("sequence") or 999999
            )
        )

        for rule in rules:
            action = rule.properties.get("action")

            if action not in ["permit", "deny"]:
                continue

            result.permitted = action == "permit"
            result.rule = rule
            result.match = self._build_acl_match(rule)
            result.reason = (
                f"Matched {action} rule {rule.name} "
                f"(sequence {rule.properties.get('sequence')})"
            )

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

            if not self._service_matches(rule, service, protocol):
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

    def _service_matches(self, rule, service, protocol=None):
        if not service:
            return True

        service_type = rule.properties.get("service_type")
        rule_service = rule.properties.get("service")

        #
        # Exact destination service
        #
        if service_type == "eq":
            return (
                str(rule_service).lower()
                == str(service).lower()
            )

        #
        # Destination port range
        #
        if service_type == "range":
            start = rule.properties.get("service_start")
            end = rule.properties.get("service_end")

            try:
                requested = int(service)
                start = int(start)
                end = int(end)
            except (TypeError, ValueError):
                return False

            return start <= requested <= end

        #
        # ASA service object-group.
        #
        if service_type == "object-group":
            return self._service_object_group_matches(
                rule_service,
                protocol,
                service
            )

        #
        # No destination port restriction.
        #
        if not service_type and not rule_service:
            return True

        #
        # Legacy exact service representation.
        #
        if rule_service is not None:
            return (
                str(rule_service).lower()
                == str(service).lower()
            )

        return False

    def _service_object_group_matches(
        self,
        group_name,
        protocol,
        service,
        visited=None
    ):
        if not group_name:
            return False

        if visited is None:
            visited = set()

        if group_name in visited:
            return False

        visited.add(group_name)

        group = self.graph.find(
            "ObjectGroup",
            group_name
        )

        if not group:
            return False

        requested_protocol = (
            str(protocol).lower()
            if protocol
            else None
        )

        requested_service = str(service).lower()

        for relation, member in self.graph.neighbors(group.id):

            if relation != "HAS_MEMBER":
                continue

            raw = str(
                member.properties.get("value")
                or member.name
                or ""
            ).strip()

            if not raw:
                continue

            parts = raw.split()

            #
            # Nested service object-group:
            # group-object SOME_GROUP
            #
            if (
                len(parts) >= 2
                and parts[0].lower() == "group-object"
            ):
                nested_group = parts[1]

                if self._service_object_group_matches(
                    nested_group,
                    protocol,
                    service,
                    visited
                ):
                    return True

                continue

            #
            # Typical ASA service-object expansion:
            #
            # tcp destination eq 88
            # udp destination eq domain
            # tcp destination range 49152 65535
            #
            if len(parts) < 4:
                continue

            member_protocol = parts[0].lower()

            if (
                requested_protocol
                and member_protocol != requested_protocol
            ):
                continue

            if "eq" in parts:
                index = parts.index("eq")

                if len(parts) > index + 1:
                    member_service = parts[index + 1].lower()

                    if member_service == requested_service:
                        return True

            if "range" in parts:
                index = parts.index("range")

                if len(parts) > index + 2:
                    try:
                        start = int(parts[index + 1])
                        end = int(parts[index + 2])
                        requested = int(service)
                    except (TypeError, ValueError):
                        continue

                    if start <= requested <= end:
                        return True

        return False

        
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

        if security_context.trace_status == "denied":
            return self._evaluate_denied(
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

    def _evaluate_denied(
        self,
        security_context: SecurityContext
    ):
        if security_context.acl_rule:
            return SecurityAssessment(
                classification="explicit_policy_deny",
                disposition="deny",
                confidence="high",
                message=(
                    "Traffic was explicitly denied by a matching ACL rule."
                ),
                device=security_context.egress_device,
                interface=security_context.ingress_interface,
                evidence=[
                    f"acl_rule={security_context.acl_rule}"
                ]
            )

        return SecurityAssessment(
            classification="no_acl_match",
            disposition="deny",
            confidence="high",
            message=(
                "Traffic was denied because no ACL rule matched."
            ),
            device=security_context.egress_device,
            interface=security_context.ingress_interface,
            evidence=[
                "implicit_deny"
            ]
        )
