from builders.graph_builder import GraphBuilder

from engines.route_engine import RouteEngine
from engines.security_engine import SecurityEngine

from workflows.trace_workflow import TraceWorkflow
from engines.application_engine import ApplicationEngine


class DigitalTwin:

    def __init__(self):

        print("Loading Knowledge Graph...")

        self.graph = GraphBuilder().build_from_vrf_inventory()

        print("Knowledge Graph loaded")

        self.security = SecurityEngine(self.graph)

        self.route = RouteEngine()

        self.trace = TraceWorkflow(self)

        self.application = ApplicationEngine(self.graph)