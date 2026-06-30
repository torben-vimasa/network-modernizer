from builders.bgp_builder import BGPBuilder
from builders.interface_builder import InterfaceBuilder


class ImportBuilder:

    def __init__(self, graph):

        self.graph = graph
        self.bgp_builder = BGPBuilder(graph)
        self.interface_builder = InterfaceBuilder(graph)

    def build(self, result):

        if result.bgp_routes:
            self.bgp_builder.add_routes(result.bgp_routes)

        if result.interfaces:
            self.interface_builder.add_interfaces(result.interfaces)