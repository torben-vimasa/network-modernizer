from builders.bgp_builder import BGPBuilder


class ImportBuilder:

    def __init__(self, graph):

        self.graph = graph

        self.bgp_builder = BGPBuilder(graph)

    def build(self, result):

        if result.bgp_routes:
            self.bgp_builder.add_routes(result.bgp_routes)

        # næste uge
        # if result.routes:
        #     RouteBuilder...
        #
        # if result.interfaces:
        #     InterfaceBuilder...
        #
        # if result.vrfs:
        #     VRFBuilder...