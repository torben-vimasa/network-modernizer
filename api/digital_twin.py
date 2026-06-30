from pathlib import Path

from builders.graph_builder import GraphBuilder
from builders.import_builder import ImportBuilder

from engines.application_engine import ApplicationEngine
from engines.nat_engine import NATEngine
from engines.route_engine import RouteEngine
from engines.security_engine import SecurityEngine
from engines.source_locator_engine import SourceLocatorEngine

from importers.asa_importer import ASAImporter
from importers.import_dispatcher import ImportDispatcher
from importers.router_importer import RouterImporter

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

        self.asa_importer = ASAImporter()
        self.router_importer = RouterImporter()
        self.dispatcher = ImportDispatcher()
        self.import_builder = ImportBuilder(self.graph)

        self.imported_config = self.asa_importer.import_config(asa_config_file)

        self.nat = NATEngine(
            self.imported_config.nat_rules
        )

        self.trace = TraceWorkflow(self)

    def load_router(self, filename):

        result = self.router_importer.import_router(filename)

        self.import_builder.build(result)

        return result

    def load_file(self, filename):

        result = self.dispatcher.import_file(filename)

        if result:
            self.import_builder.build(result)

        return result

    def load_directory(self, directory):

        directory = Path(directory)

        imported = 0

        for file in directory.rglob("*.txt"):

            result = self.load_file(file)

            if result:
                imported += 1

        print()
        print(f"Imported {imported} files.")

    def trace_packet(
        self,
        source,
        destination,
        protocol=None,
        service=None,
        router=None,
        vrf=None,
        route_destination=None
    ):

        locator = SourceLocatorEngine(self.graph)

        location = locator.locate(source)

        if location.get("found"):

            router = router or location.get("device")
            vrf = vrf or location.get("vrf")

        if not router or not vrf:

            print()
            print("Source location")
            print("=" * 60)
            print(location)
            print()
            print("Trace requires router and VRF until source inventory is complete.")

            return None

        return self.trace.trace(
            source=source,
            destination=destination,
            protocol=protocol,
            service=service,
            router=router,
            vrf=vrf,
            route_destination=route_destination or destination
        )

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