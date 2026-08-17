import json
from pathlib import Path

from graph.graph import KnowledgeGraph
from inventory.inventory import Inventory
from parsers.acl_rule_parser import ACLRuleParser
from parsers.router_inventory_parser import RouterInventoryParser
from utils.firewall_context import detect_firewall_context


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

        self._add_firewall_interfaces(graph)
        self._add_access_groups(graph)
        self._add_router_interfaces(graph)
        self._add_firewall_bgp(graph)
        
        self._connect_bgp_neighbors(graph)
        self._connect_bgp_to_firewall_interfaces(graph)
        self._connect_interfaces_by_subnet(graph)
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

        #
        # Add all concrete network objects first.
        #
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

        #
        # First create all ObjectGroup nodes.
        #
        groups = []

        if object_groups_file.exists():
            groups = self._load_json("object_groups.json")

            for group in groups:
                graph.add_node(
                    "ObjectGroup",
                    group["name"],
                    {
                        "member_count": len(group["members"])
                    }
                )

        #
        # Then create HAS_MEMBER relationships.
        #
        # Doing this as a second pass ensures nested ObjectGroups
        # already exist before we resolve group-object references.
        #
        for group in groups:
            group_node_id = f"ObjectGroup:{group['name']}"

            for member in group["members"]:

                #
                # Prefer an already parsed NetworkObject.
                #
                existing_node = graph.find(
                    "NetworkObject",
                    member
                )

                if existing_node:
                    member_id = existing_node.id

                else:
                    #
                    # group-object may reference another ObjectGroup.
                    #
                    existing_group = graph.find(
                        "ObjectGroup",
                        member
                    )

                    if existing_group:
                        member_id = existing_group.id

                    else:
                        #
                        # Only create a raw placeholder when the
                        # referenced object/group is genuinely unknown.
                        #
                        member_id = graph.add_node(
                            "NetworkObject",
                            member,
                            {
                                "type": "raw_member",
                                "value": member
                            }
                        )

                graph.add_relationship(
                    group_node_id,
                    member_id,
                    "HAS_MEMBER"
                )

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
                        "service_type": getattr(rule, "service_type", None),
                        "service_start": getattr(rule, "service_start", None),
                        "service_end": getattr(rule, "service_end", None),
                        "hitcnt": rule.hitcnt,
                        "source_type": getattr(rule, "source_type", None),
                        "source_value": getattr(rule, "source_value", None),
                        "destination_type": getattr(rule, "destination_type", None),
                        "destination_value": getattr(rule, "destination_value", None),

                        "context": rule.properties.get("context"),
                        "source_ifc": rule.properties.get("source_ifc"),
                        "destination_ifc": rule.properties.get("destination_ifc"),

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


        if endpoint_type == "network":
            target_node = graph.add_node(
                "NetworkObject",
                endpoint_value,
                {
                    "type": "network",
                    "value": endpoint_value
                }
            )

            graph.add_relationship(
                rule_node,
                target_node,
                relationship_type
            )
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

        for router_file in router_dir.rglob("*section interface*.txt"):
            with open(router_file, encoding="utf-8", errors="ignore") as f:
                router = self.router_parser.parse(
                    router_file.parent.name,
                    f.readlines()
                )

            router_node = graph.add_node(
                "Router",
                router.name
            )

            for interface in router.interfaces:
                interface_node = graph.add_node(
                    "RouterInterface",
                    f"{router.name}:{interface.name}",
                    {
                        "vrf": interface.vrf,
                        "ip": interface.ip,
                        "prefix": interface.prefix,
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

    def _add_firewall_interfaces(self, graph):
        interfaces_file = self.output_dir / "firewall_interfaces.json"

        if not interfaces_file.exists():
            return

        interfaces = self._load_json("firewall_interfaces.json")

        for interface in interfaces:
            firewall_node = graph.add_node(
                "Firewall",
                interface["device"]
            )

            interface_name = interface.get("nameif") or interface["interface"]

            interface_node = graph.add_node(
                "ASAInterface",
                f'{interface["device"]}:{interface_name}',
                {
                    "device": interface["device"],
                    "context": interface.get("context") or interface["device"],
                    "interface": interface["interface"],
                    "nameif": interface.get("nameif"),
                    "vlan": interface.get("vlan"),
                    "ip": interface.get("ip"),
                    "mask": interface.get("mask"),
                    "description": interface.get("description"),
                    "security_level": interface.get("security_level")
                }
            )

            graph.add_relationship(
                firewall_node,
                interface_node,
                "HAS_INTERFACE"
            )

            if interface.get("ip") and interface.get("mask"):
                subnet = self._to_prefix(
                    interface["ip"],
                    interface["mask"]
                )

                subnet_node = graph.add_node(
                    "Subnet",
                    subnet,
                    {
                        "prefix": subnet
                    }
                )

                graph.add_relationship(
                    interface_node,
                    subnet_node,
                    "IN_SUBNET"
                )

    def _to_prefix(self, ip, mask):
        import ipaddress

        return str(
            ipaddress.ip_network(
                f"{ip}/{mask}",
                strict=False
        )
    )

    def _connect_interfaces_by_subnet(self, graph):

        subnet_members = {}

        for relationship in graph.relationships:

            if relationship.type != "IN_SUBNET":
                continue

            subnet_members.setdefault(
                relationship.target,
                []
            ).append(relationship.source)

        for subnet, interfaces in subnet_members.items():

            if len(interfaces) < 2:
                continue

            for i in range(len(interfaces)):
                for j in range(i + 1, len(interfaces)):

                    a = interfaces[i]
                    b = interfaces[j]

                    graph.add_relationship(
                        a,
                        b,
                        "CONNECTED_TO"
                    )

                    graph.add_relationship(
                        b,
                        a,
                        "CONNECTED_TO"
                    )


    def _add_firewall_bgp(self, graph):

        file = self.output_dir / "firewall_bgp_neighbors.json"

        if not file.exists():
            return

        neighbors = self._load_json("firewall_bgp_neighbors.json")

        for n in neighbors:

            fw = graph.add_node(
                "Firewall",
                n["device"]
            )

            peer = graph.add_node(
                "BGPNeighbor",
                n["neighbor"],
                {
                    "remote_as": n["remote_as"],
                    "description": n["description"],
                    "local_as": n["local_as"],
                    "route_map_in": n["route_map_in"],
                    "route_map_out": n["route_map_out"],
                    "prefix_list_in": n["prefix_list_in"],
                    "prefix_list_out": n["prefix_list_out"],
                    "activated": n["activated"]
                }
            )

            graph.add_relationship(
                fw,
                peer,
                "HAS_BGP_NEIGHBOR"
            )

    def _connect_bgp_neighbors(self, graph):

        router_interfaces = []

        for node in graph.nodes.values():

            if node.type not in ["RouterInterface", "Interface"]:
                continue

            router_interfaces.append(
                {
                    "node": node,
                    "ip": node.properties.get("ip"),
                    "hsrp_virtual_ip": node.properties.get("hsrp_virtual_ip")
                }
            )

        for node in graph.nodes.values():

            if node.type != "BGPNeighbor":
                continue

            peer = node.name

            for entry in router_interfaces:

                rif = entry["node"]

                match_type = None

                if entry["ip"] == peer:
                    match_type = "interface_ip"

                elif entry["hsrp_virtual_ip"] == peer:
                    match_type = "hsrp_virtual_ip"

                if not match_type:
                    continue

                graph.add_relationship(
                    node.id,
                    rif.id,
                    "PEERS_WITH",
                    {"match_type": match_type}
                )

                graph.add_relationship(
                    rif.id,
                    node.id,
                    "PEER_OF",
                    {"match_type": match_type}
                )

    def _add_router_interfaces(self, graph):

        file = self.output_dir / "router_interfaces.json"

        if not file.exists():
            return

        interfaces = self._load_json("router_interfaces.json")

        hsrp_states = self._load_json("hsrp_status.json")

        hsrp_by_key = {
            (
                h.get("device"),
                h.get("interface"),
                h.get("virtual_ip")
            ): h
            for h in hsrp_states
        }

        for i in interfaces:

            router = graph.add_node(
                "Router",
                i["device"]
            )

            hsrp = hsrp_by_key.get(
                (
                    i["device"],
                    i["interface"],
                    i.get("hsrp_virtual_ip")
                )
            )

            interface = graph.add_node(
                "RouterInterface",
                f'{i["device"]}:{i["interface"]}',
                {
                    "ip": i["ip"],
                    "mask": i.get("mask"),
                    "hsrp_virtual_ip": i["hsrp_virtual_ip"],
                    "hsrp_state": hsrp.get("state") if hsrp else i.get("hsrp_state"),
                    "hsrp_priority": i.get("hsrp_priority"),
                    "vrf": i.get("vrf")
                }
            )
            graph.add_relationship(
                router,
                interface,
                "HAS_INTERFACE"
            )

            if i["ip"] and i.get("mask"):
                prefix = self._to_prefix_from_cidr_or_host(
                    i["ip"],
                    i.get("mask")
                )

                if prefix:
                    subnet = graph.add_node(
                        "Subnet",
                        prefix,
                        {"prefix": prefix}
                    )

                    graph.add_relationship(
                        interface,
                        subnet,
                        "IN_SUBNET"
                    )

    def _connect_bgp_to_firewall_interfaces(self, graph):

        for bgp in graph.nodes.values():

            if bgp.type != "BGPNeighbor":
                continue

            peer = bgp.name

            for rel in graph.relationships:

                if rel.type != "IN_SUBNET":
                    continue

                source = graph.nodes.get(rel.source)
                subnet = graph.nodes.get(rel.target)

                if not source or not subnet:
                    continue

                if source.type != "ASAInterface":
                    continue

                prefix = subnet.properties.get("prefix") or subnet.name

                import ipaddress

                if ipaddress.ip_address(peer) not in ipaddress.ip_network(prefix):
                    continue

                graph.add_relationship(
                    source.id,
                    bgp.id,
                    "HAS_BGP_NEIGHBOR",
                    {"match_type": "same_subnet"}
                )

                graph.add_relationship(
                    bgp.id,
                    source.id,
                    "BGP_ON_INTERFACE",
                    {"match_type": "same_subnet"}
                )

    def _to_prefix_from_cidr_or_host(self, ip, mask=None):
        import ipaddress

        if not ip:
            return None

        if "/" in str(ip):
            return str(ipaddress.ip_network(ip, strict=False))

        if mask:
            return str(ipaddress.ip_network(f"{ip}/{mask}", strict=False))

        return None

    def _add_access_groups(self, graph):
        file = self.output_dir / "access_groups.json"

        if not file.exists():
            return

        access_groups = self._load_json("access_groups.json")

        for entry in access_groups:
            context = entry.get("context") or entry.get("device")
            interface = (
                entry.get("asa_interface")
                or entry.get("interface")
            )
            acl_name = entry.get("acl")
            direction = entry.get("direction")

            if not context or not acl_name:
                continue

            #
            # FTD global ACL
            #
            # access-group CSM_FW_ACL_ global
            #
            if direction == "global":
                firewall_node = graph.find(
                    "Firewall",
                    context
                )

                if not firewall_node:
                    continue

                acl_node = graph.add_node(
                    "ACL",
                    acl_name
                )

                graph.add_relationship(
                    firewall_node.id,
                    acl_node,
                    "USES_GLOBAL_ACL"
                )

                continue

            #
            # Classic ASA interface ACL
            #
            if not interface:
                continue

            interface_node = None

            for node in graph.nodes.values():

                if node.type != "ASAInterface":
                    continue

                if node.properties.get("context") != context:
                    continue

                if (
                    node.properties.get("nameif") == interface
                    or
                    node.properties.get("interface") == interface
                ):
                    interface_node = node
                    break

            if not interface_node:
                continue

            acl_node = graph.add_node(
                "ACL",
                acl_name
            )

            graph.add_relationship(
                interface_node.id,
                acl_node,
                "USES_ACL",
                {
                    "direction": direction
                }
            )