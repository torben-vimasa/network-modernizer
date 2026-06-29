from builders.graph_builder import GraphBuilder

from engines.application_engine import ApplicationEngine
from engines.nat_engine import NATEngine
from engines.route_engine import RouteEngine
from engines.security_engine import SecurityEngine

from importers.asa_importer import ASAImporter

from models.application_trace_result import ApplicationTraceResult

from workflows.trace_workflow import TraceWorkflow


class DigitalTwin:

    def __init__(self, asa_config_file="data/asa_nat_sample.txt"):

        print("Loading Knowledge Graph...")

        self.graph = GraphBuilder().build_from_vrf_inventory()

        print("Knowledge Graph loaded")

        self.security = SecurityEngine(self.graph)
        self.route = RouteEngine()
        self.application = ApplicationEngine(self.graph)

        self.importer = ASAImporter()
        self.imported_config = self.importer.import_config(asa_config_file)

        self.nat = NATEngine(
            self.imported_config.nat_rules
        )

        self.trace = TraceWorkflow(self)

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