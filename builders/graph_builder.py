import json
from pathlib import Path

from graph.graph import KnowledgeGraph


class GraphBuilder:
    def __init__(self):
        self.output_dir = Path("output")

    def build_from_vrf_inventory(self):
        vrf_inventory = self._load_json("vrf_inventory.json")
        vrf_topology = self._load_json("vrf_asa_topology.json")

        graph = KnowledgeGraph()

        self._add_vrf_nodes(graph, vrf_inventory)
        self._add_topology_links(graph, vrf_topology)

        return graph

    def _load_json(self, filename):
        with open(self.output_dir / filename, "r") as f:
            return json.load(f)

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
                self._add_topology_link(graph, vrf_node, link)

    def _add_topology_link(self, graph, vrf_node, link):
        context_node = graph.add_node("Context", link["asa_context"])

        asa_interface_node = self._add_asa_interface(graph, link)

        graph.add_relationship(
            context_node,
            asa_interface_node,
            "HAS_INTERFACE"
        )

        graph.add_relationship(
            asa_interface_node,
            vrf_node,
            "BELONGS_TO_VRF"
        )

        self._add_acl(graph, asa_interface_node, vrf_node, link)

        router_node = graph.add_node("Router", link["router"])
        router_interface_node = self._add_router_interface(graph, link)

        graph.add_relationship(
            router_node,
            router_interface_node,
            "HAS_INTERFACE"
        )

        graph.add_relationship(
            router_interface_node,
            vrf_node,
            "BELONGS_TO_VRF"
        )

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

    def _add_asa_interface(self, graph, link):
        name = f'{link["asa_context"]}:{link["asa_interface"]}'

        return graph.add_node(
            "ASAInterface",
            name,
            {
                "context": link["asa_context"],
                "interface": link["asa_interface"],
                "ip": link["asa_ip"],
                "subnet": link["asa_subnet"]
            }
        )

    def _add_router_interface(self, graph, link):
        name = f'{link["router"]}:{link["router_interface"]}'

        return graph.add_node(
            "RouterInterface",
            name,
            {
                "router": link["router"],
                "interface": link["router_interface"],
                "ip": link["router_ip"]
            }
        )

    def _add_acl(self, graph, asa_interface_node, vrf_node, link):
        if not link["asa_access_group"]:
            return

        acl_node = graph.add_node("ACL", link["asa_access_group"])

        graph.add_relationship(
            asa_interface_node,
            acl_node,
            "USES_ACL"
        )

        graph.add_relationship(
            acl_node,
            vrf_node,
            "PROTECTS"
        )