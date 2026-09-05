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
        ingress_interface=None,
        egress_interface=None,
        defer_global_acl=False
        
    ):
        result = SecurityResult()

        rules = self._matching_rules(
            source,
            destination,
            protocol,
            service
        )

        #
        # During firewall pre-check we may not know the egress
        # interface yet. FTD global ACL evaluation is therefore
        # deferred until firewall routing has resolved egress.
        #
        if defer_global_acl and context and not egress_interface:
            firewall = self.graph.find(
                "Firewall",
                context
            )

            has_global_acl = False

            if firewall:
                for relation, neighbor in self.graph.neighbors(
                    firewall.id
                ):
                    if (
                        relation == "USES_GLOBAL_ACL"
                        and neighbor.type == "ACL"
                    ):
                        has_global_acl = True
                        break

            if has_global_acl:
                result.permitted = True
                result.reason = (
                    "Global ACL evaluation deferred until "
                    "firewall egress interface is resolved"
                )
                return result

        if context or ingress_interface or egress_interface:
            rules = [
                rule
                for rule in rules
                if self._rule_applies_to_interface(
                    rule,
                    context,
                    ingress_interface,
                    egress_interface
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
            # FTD service group port-object:
            #
            # eq 1514
            # range 49152 65535
            #
            if len(parts) >= 2 and parts[0].lower() == "eq":
                member_service = parts[1].lower()

                if member_service == requested_service:
                    return True

                continue

            if len(parts) >= 3 and parts[0].lower() == "range":
                try:
                    start = int(parts[1])
                    end = int(parts[2])
                    requested = int(service)
                except (TypeError, ValueError):
                    continue

                if start <= requested <= end:
                    return True

                continue


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
        object_type = node.properties.get("type")

        #
        # Object-group members may be references to another
        # context-scoped NetworkObject.
        #
        if object_type == "raw_member" and object_value:
            referenced_node = self.graph.find(
                "NetworkObject",
                object_value
            )

            if (
                referenced_node
                and referenced_node.id != node.id
            ):
                return self._network_object_matches(
                    referenced_node,
                    value
                )

            referenced_group = self.graph.find(
                "ObjectGroup",
                object_value
            )

            if referenced_group:
                return self._object_group_matches(
                    referenced_group,
                    value
                )

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

        #
        # Generic IPv4/IPv6 address and CIDR matching.
        #
        # Security evaluation asks whether the policy object
        # covers the complete requested value.
        #
        # Examples:
        #
        #   policy 10.0.0.0/8, query 10.3.0.0/16
        #       -> True
        #
        #   policy 10.3.32.0/19, query 10.3.0.0/16
        #       -> False
        #
        #   policy 10.3.32.0/19, query 10.3.32.17
        #       -> True
        #
        if object_type in ["network", "subnet"] and object_value:
            try:
                policy_network = ipaddress.ip_network(
                    object_value,
                    strict=False
                )

                query_text = str(value).strip()

                if "/" in query_text:
                    query_network = ipaddress.ip_network(
                        query_text,
                        strict=False
                    )

                    if (
                        policy_network.version
                        != query_network.version
                    ):
                        return False

                    return query_network.subnet_of(
                        policy_network
                    )

                query_address = ipaddress.ip_address(
                    query_text
                )

                if (
                    policy_network.version
                    != query_address.version
                ):
                    return False

                return query_address in policy_network

            except (TypeError, ValueError):
                return False

        return False

    def _object_group_matches(
        self,
        node,
        value,
        visited=None
    ):
        if visited is None:
            visited = set()

        if node.id in visited:
            return False

        visited.add(node.id)

        for relation, member in self.graph.neighbors(node.id):
            if relation != "HAS_MEMBER":
                continue

            if member.type == "NetworkObject":
                if self._network_object_matches(
                    member,
                    value
                ):
                    return True

            elif member.type == "ObjectGroup":
                if self._object_group_matches(
                    member,
                    value,
                    visited
                ):
                    return True

        return False

    def _rule_applies_to_interface(
        self,
        rule,
        context,
        ingress_interface,
        egress_interface=None
    ):
        acl_name = rule.properties.get("acl")

        if not acl_name:
            return False

        #
        # If rule carries an explicit context, it must match
        # the firewall currently being evaluated.
        #
        rule_context = rule.properties.get("context")

        if (
            rule_context
            and rule_context != context
        ):
            return False

        #
        # FTD advanced rules may explicitly specify
        # the source/ingress interface.
        #
        source_ifc = rule.properties.get("source_ifc")

        if (
            source_ifc
            and source_ifc != ingress_interface
        ):
            return False

        destination_ifc = rule.properties.get(
            "destination_ifc"
        )

        if (
            destination_ifc
            and egress_interface
            and destination_ifc != egress_interface
        ):
            return False

        #
        # Classic ASA interface ACL
        #
        for node in self.graph.nodes.values():
            if node.type != "ASAInterface":
                continue

            if node.properties.get("context") != context:
                continue

            interface_matches = (
                node.properties.get("nameif") == ingress_interface
                or
                node.properties.get("interface") == ingress_interface
            )

            if not interface_matches:
                continue

            acl_node = self.graph.find(
                "ACL",
                acl_name
            )

            if not acl_node:
                continue

            for relationship in self.graph.relationships:

                if relationship.type != "USES_ACL":
                    continue

                if relationship.source != node.id:
                    continue

                if relationship.target != acl_node.id:
                    continue

                direction = relationship.properties.get(
                    "direction"
                )

                #
                # We are evaluating traffic arriving on
                # ingress_interface, so only an inbound ACL
                # on that interface applies here.
                #
                if direction and direction.lower() != "in":
                    continue

                return True

        #
        # FTD global ACL
        #
        firewall = self.graph.find(
            "Firewall",
            context
        )

        if firewall:
            for relation, neighbor in self.graph.neighbors(
                firewall.id
            ):
                if (
                    relation == "USES_GLOBAL_ACL"
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

        if security_context.acl_permitted is True:
            return self._evaluate_permitted(
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

    def _evaluate_permitted(
        self,
        security_context: SecurityContext
    ):
        evidence = []

        if security_context.firewall_traversed:
            evidence.append("firewall_traversed")

        evidence.append("acl_permitted")

        if security_context.acl_rule:
            evidence.append(
                f"acl_rule={security_context.acl_rule}"
            )

        if security_context.ingress_interface:
            evidence.append(
                f"ingress_interface={security_context.ingress_interface}"
            )

        if security_context.ingress_device:
            evidence.append(
                f"ingress_device={security_context.ingress_device}"
            )

        return SecurityAssessment(
            classification="permitted_by_policy",
            disposition="allow",
            confidence="high",
            message="Traffic was permitted by a matching ACL rule.",
            device=security_context.ingress_device,
            interface=security_context.ingress_interface,
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
