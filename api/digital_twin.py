from builders.graph_builder import GraphBuilder

from engines.application_engine import ApplicationEngine
from engines.nat_engine import NATEngine
from engines.route_engine import RouteEngine
from engines.security_engine import SecurityEngine

from models.application_trace_result import ApplicationTraceResult
from models.nat_rule import NATRule

from parsers.asa_nat_parser import ASANATParser

from workflows.trace_workflow import TraceWorkflow


class DigitalTwin:

    def __init__(self):

        print("Loading Knowledge Graph...")

        self.graph = GraphBuilder().build_from_vrf_inventory()

        print("Knowledge Graph loaded")

        self.security = SecurityEngine(self.graph)
        self.route = RouteEngine()
        self.application = ApplicationEngine(self.graph)

        self.nat = self._load_nat_engine()

        self.trace = TraceWorkflow(self)

    def _load_nat_engine(self):

        nat_file = "data/asa_nat_sample.txt"

        parser = ASANATParser()

        rules = parser.parse_file(nat_file)

        return NATEngine(rules)

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

        app = self.graph.find("Application", application)

        if not app:
            return None

        packets = self.application.build_packets(application)

        result = ApplicationTraceResult(
            application=app.name,
            criticality=app.properties.get("criticality"),
            max_outage_minutes=app.properties.get("max_outage_minutes")
        )

        for packet in packets:

            trace = self.trace.trace(
                source=packet.source,
                destination=packet.destination,
                protocol=packet.protocol,
                service=packet.service,
                router=router,
                vrf=vrf,
                route_destination=route_destination or packet.destination
            )

            result.traces.append(trace)

        return result