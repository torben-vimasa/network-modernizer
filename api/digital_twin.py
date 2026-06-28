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

    def trace_application(
        self,
        application,
        router,
        vrf,
        route_destination=None
    ):

        packet = self.application.build_packet(application)

        if not packet:
            return None

        return self.trace.trace(
            source=packet.source,
            destination=packet.destination,
            protocol=packet.protocol,
            service=packet.service,
            router=router,
            vrf=vrf,
            route_destination=route_destination or packet.destination
        )

    def trace_application_flows(
        self,
        application,
        router,
        vrf,
        route_destination=None
    ):

        packets = self.application.build_packets(application)

        results = []

        for packet in packets:

            result = self.trace.trace(
                source=packet.source,
                destination=packet.destination,
                protocol=packet.protocol,
                service=packet.service,
                router=router,
                vrf=vrf,
                route_destination=route_destination or packet.destination
            )

            results.append(result)

        return results