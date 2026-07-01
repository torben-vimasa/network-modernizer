import json
from pathlib import Path

from graph.graph import KnowledgeGraph
from inventory.inventory import Inventory
from parsers.acl_rule_parser import ACLRuleParser
from parsers.router_inventory_parser import RouterInventoryParser


class GraphBuilder:
    def __init__(self):
        self.output_dir = Path("output")
        self.knowledge_dir = Path("knowledge")
        self.router_parser = RouterInventoryParser()

        self.inventory = Inventory()

    def build_from_vrf_inventory(self):
        graph = KnowledgeGraph()

        vrf_inventory = self._load_json("vrf_inventory.json")
        vrf_topology = self._load_json("vrf_asa_topology.json")

        self._add_vrf_nodes(graph, vrf_inventory)
        self._add_topology_links(graph, vrf_topology)
        self._add_objects_and_groups(graph)
        self._add_acl_rules(graph)
        self._add_router_inventory(graph)
        self._add_applications(graph)

        return graph

    def _load_json(self, filename):
        with open(self.output_dir / filename, "r") as f:
            return json.load(f)

    def _load_knowledge(self, filename):
        with open(self.knowledge_dir / filename, "r", encoding="utf-8") as f:
            return json.load(f)

    def _resolve_firewall_name(self, context_name, fallback=None):
        firewall = self.inventory.context(context_name)

        if firewall:
            return firewall.name

        return fallback or "UnknownFirewall"

    def _add_vrf_nodes(self, graph, vrf_inventory):
        for vrf_name, vrf in vrf_inventory.items():
            graph.add_node(
                "VRF",
                vrf_name,
                {
                    "complexity_score": vrf["complexity_score"],
                    "link_count": vrf["link_count"]
                }
            )

    def _add_topology_links(self, graph, vrf_topology):
        for vrf_name, links in vrf_topology.items():
            vrf_node = graph.add_node("VRF", vrf_name)

            for link in links:
                context_name = link["asa_context"]

                context_node = graph.add_node(
                    "Context",
                    context_name
                )

                firewall_name = self._resolve_firewall_name(
                    context_name,
                    fallback=link.get("asa_firewall")
                )

                firewall_node = graph.add_node(
                    "Firewall",
                    firewall_name
                )

                graph.add_relationship(
                    firewall_node,
                    context_node,
                    "HAS_CONTEXT"
                )

                asa_interface_node = graph.add_node(
                    "ASAInterface",
                    f'{link["asa_context"]}:{link["asa_interface"]}',
                    {
                        "context": link["asa_context"],
                        "interface": link["asa_interface"],
                        "ip": link["asa_ip"],
                        "subnet": link["asa_subnet"]
                    }
                )

                graph.add_relationship(context_node, asa_interface_node, "HAS_INTERFACE")
                graph.add_relationship(asa_interface_node, vrf_node, "BELONGS_TO_VRF")

                if link["asa_access_group"]:
                    acl_node = graph.add_node("ACL", link["asa_access_group"])
                    graph.add_relationship(asa_interface_node, acl_node, "USES_ACL")
                    graph.add_relationship(acl_node, vrf_node, "PROTECTS")

                router_node = graph.add_node("Router", link["router"])

                router_interface_node = graph.add_node(
                    "RouterInterface",
                    f'{link["router"]}:{link["router_interface"]}',
                    {
                        "router": link["router"],
                        "interface": link["router_interface"],
                        "ip": link["router_ip"]
                    }
                )

                graph.add_relationship(router_node, router_interface_node, "HAS_INTERFACE")
                graph.add_relationship(router_interface_node, vrf_node, "BELONGS_TO_VRF")

                graph.add_relationship(
                    asa_interface_node,
                    router_interface_node,
                    "CONNECTED_TO",
                    {
                        "asa_ip": link["asa_ip"],
                        "router_ip": link["router_ip"],
                        "subnet": link["asa_subnet"]
                    }
                )

    def _add_objects_and_groups(self, graph):
        network_objects_file = self.output_dir / "network_objects.json"
        object_groups_file = self.output_dir / "object_groups.json"

        if network_objects_file.exists():
            for obj in self._load_json("network_objects.json"):
                graph.add_node(
                    "NetworkObject",
                    obj["name"],
                    {
                        "type": obj["type"],
                        "value": obj["value"]
                    }
                )

        if object_groups_file.exists():
            for group in self._load_json("object_groups.json"):
                group_node = graph.add_node(
                    "ObjectGroup",
                    group["name"],
                    {
                        "member_count": len(group["members"])
                    }
                )

                for member in group["members"]:
                    member_node = graph.add_node(
                        "NetworkObject",
                        member,
                        {
                            "type": "raw_member",
                            "value": member
                        }
                    )

                    graph.add_relationship(group_node, member_node, "HAS_MEMBER")

    def _add_acl_rules(self, graph):
        rules_file = self.output_dir / "rules.json"

        if not rules_file.exists():
            return

        raw_rules = self._load_json("rules.json")
        acls = ACLRuleParser().parse_rules(raw_rules)

        for acl in acls:
            acl_node = graph.add_node("ACL", acl.name)

            for rule in acl.rules:
                rule_node = graph.add_node(
                    "ACLRule",
                    f"{acl.name}:{rule.sequence}",
                    {
                        "acl": rule.acl_name,
                        "sequence": rule.sequence,
                        "action": rule.action,
                        "protocol": rule.protocol,
                        "source": rule.source,
                        "destination": rule.destination,
                        "service": rule.service,
                        "hitcnt": rule.hitcnt,
                        "source_type": getattr(rule, "source_type", None),
                        "source_value": getattr(rule, "source_value", None),
                        "destination_type": getattr(rule, "destination_type", None),
                        "destination_value": getattr(rule, "destination_value", None),
                        "raw": rule.properties.get("raw")
                    }
                )

                graph.add_relationship(acl_node, rule_node, "HAS_RULE")

                self._connect_acl_rule_endpoint(
                    graph,
                    rule_node,
                    "USES_SOURCE",
                    getattr(rule, "source_type", None),
                    getattr(rule, "source_value", None)
                )

                self._connect_acl_rule_endpoint(
                    graph,
                    rule_node,
                    "USES_DESTINATION",
                    getattr(rule, "destination_type", None),
                    getattr(rule, "destination_value", None)
                )

    def _connect_acl_rule_endpoint(
        self,
        graph,
        rule_node,
        relationship_type,
        endpoint_type,
        endpoint_value
    ):
        if not endpoint_type or not endpoint_value:
            return

        if endpoint_type == "any":
            target_node = graph.add_node(
                "NetworkObject",
                "any",
                {
                    "type": "any",
                    "value": "any"
                }
            )
            graph.add_relationship(rule_node, target_node, relationship_type)
            return

        if endpoint_type == "host":
            target_node = graph.add_node(
                "NetworkObject",
                endpoint_value,
                {
                    "type": "host",
                    "value": endpoint_value
                }
            )
            graph.add_relationship(rule_node, target_node, relationship_type)
            return

        if endpoint_type == "object":
            target_node = self._find_best_node(graph, "NetworkObject", endpoint_value)
            if target_node:
                graph.add_relationship(rule_node, target_node, relationship_type)
            return

        if endpoint_type == "object-group":
            target_node = self._find_best_node(graph, "ObjectGroup", endpoint_value)
            if target_node:
                graph.add_relationship(rule_node, target_node, relationship_type)
            return

    def _find_best_node(self, graph, node_type, short_name):
        exact = graph.find(node_type, short_name)

        if exact:
            return exact.id

        matches = [
            node
            for node in graph.nodes.values()
            if node.type == node_type
            and node.name.endswith(f":{short_name}")
        ]

        if not matches:
            return None

        return sorted(matches, key=lambda node: node.name)[0].id

    def _add_router_inventory(self, graph):
        router_dir = Path("data/router_raw")

        if not router_dir.exists():
            return

        for router_file in router_dir.glob("*.txt"):
            with open(router_file, encoding="utf-8", errors="ignore") as f:
                router = self.router_parser.parse(
                    router_file.stem,
                    f.readlines()
                )

            router_node = graph.add_node(
                "Router",
                router.name
            )

            for interface in router.interfaces:
                interface_node = graph.add_node(
                    "Interface",
                    f"{router.name}:{interface.name}",
                    {
                        "vrf": interface.vrf,
                        "description": interface.description
                    }
                )

                graph.add_relationship(
                    router_node,
                    interface_node,
                    "HAS_INTERFACE"
                )

                if interface.ip:
                    ip_node = graph.add_node(
                        "IPAddress",
                        interface.ip,
                        {
                            "address": interface.ip
                        }
                    )

                    graph.add_relationship(
                        interface_node,
                        ip_node,
                        "HAS_IP"
                    )

                if interface.prefix:
                    subnet_node = graph.add_node(
                        "Subnet",
                        interface.prefix,
                        {
                            "prefix": interface.prefix
                        }
                    )

                    graph.add_relationship(
                        interface_node,
                        subnet_node,
                        "IN_SUBNET"
                    )

    def _add_applications(self, graph):
        applications_file = self.knowledge_dir / "applications.json"

        if not applications_file.exists():
            return

        applications = self._load_knowledge("applications.json")

        for app in applications:
            app_node = graph.add_node(
                "Application",
                app["name"],
                {
                    "business_service": app["business_service"],
                    "owner": app["owner"],
                    "criticality": app["criticality"],
                    "max_outage_minutes": app["max_outage_minutes"],
                    "description": app["description"]
                }
            )

            for flow in app["flows"]:
                flow_node = graph.add_node(
                    "ApplicationFlow",
                    f'{app["name"]}:{flow["service"]}',
                    flow
                )

                graph.add_relationship(
                    app_node,
                    flow_node,
                    "HAS_FLOW"
                )