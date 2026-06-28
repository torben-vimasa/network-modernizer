from graph.graph import KnowledgeGraph
from models.packet import Packet


class ApplicationEngine:

    def __init__(self, graph: KnowledgeGraph):
        self.graph = graph

    def build_packet(self, application_name):

        app = self.graph.find("Application", application_name)

        if not app:
            return None

        for relation, flow in self.graph.neighbors(app.id):

            if relation != "HAS_FLOW":
                continue

            return Packet(
                source=flow.properties["source"],
                destination=flow.properties["destination"],
                protocol=flow.properties["protocol"],
                service=flow.properties["service"]
            )

        return None