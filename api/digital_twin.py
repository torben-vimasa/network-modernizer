from pathlib import Path
import json
from models.route_entry import RouteEntry

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
from models.security_context import SecurityContext

from engines.endpoint_resolver import EndpointResolver
from engines.dependency_resolver import DependencyResolver

from engines.application_view_engine import ApplicationViewEngine
from engines.object_resolver import ObjectResolver

from engines.communication_model_engine import CommunicationModelEngine
from engines.application_model_engine import ApplicationModelEngine
from engines.forwarding_engine import ForwardingEngine
from engines.flow_trace_engine import FlowTraceEngine

from graph.graph_cache import GraphCache
from engines.impact_engine import ImpactEngine


class DigitalTwin:

    def __init__(self, asa_config_file="data/asa_nat_sample.txt"):

        print("Loading Knowledge Graph...")

        graph_builder = GraphBuilder()

        self.graph = GraphCache(
            graph_builder
        ).load_or_build()

        print("Knowledge Graph loaded")

        self.security = SecurityEngine(self.graph)
        self.route = RouteEngine()

        self.firewall_routes = self._load_firewall_routes()

        self.endpoint = EndpointResolver(
            self.graph,
            routes=(
                self.route.routes
                + [
                    {
                        "router": r.router,
                        "vrf": r.vrf,
                        "prefix": r.prefix,
                        "next_hop": r.next_hop,
                        "protocol": r.protocol,
                        "interface": getattr(
                            r,
                            "interface",
                            None
                        ),
                        "egress_interface": getattr(
                            r,
                            "egress_interface",
                            None
                        )
                    }
                    for r in self.firewall_routes
                ]
            )
        )

        self.dependency = DependencyResolver(
            self.graph,
            self.endpoint
        )

        self.forwarding = ForwardingEngine(
    self.graph
)

        self.flow_trace_engine = FlowTraceEngine(
            graph=self.graph,
            endpoint_resolver=self.endpoint,
            route_engine=self.route,
            forwarding_engine=self.forwarding,
            firewall_routes=self.firewall_routes,
            dependency_resolver=self.dependency,
            security_engine=self.security
        )

        self.impact = ImpactEngine()
        self.object_resolver = ObjectResolver(
            self.graph
        )

        self.application_view = ApplicationViewEngine(
                    self.graph,
                    self.endpoint,
                    self.dependency
                )
                
        self.communication_model = CommunicationModelEngine(
            graph=self.graph,
            object_resolver=self.object_resolver,
            endpoint_resolver=self.endpoint,
            dependency_resolver=self.dependency
        )

        self.application_model = ApplicationModelEngine(
            application_view=self.application_view,
            communication_model=self.communication_model
        )

        
        self.firewall_interfaces = self._load_firewall_interfaces()
        self.application = ApplicationEngine(self.graph)

        self.asa_importer = ASAImporter()
        self.router_importer = RouterImporter()
        self.dispatcher = ImportDispatcher()
        self.import_builder = ImportBuilder(self.graph)

        self.imported_config = self.asa_importer.import_config(asa_config_file)

        self.nat_rules = self._load_nat_rules()

        self.nat = NATEngine(
            self.nat_rules,
            graph=self.graph
)

        from engines.firewall_traversal_engine import (
            FirewallTraversalEngine
        )

        self.flow_trace_engine.firewall_traversal_engine = (
            FirewallTraversalEngine(
                twin=self,
                routes=self.firewall_routes,
                interfaces=self.firewall_interfaces
            )
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

        trace = self.trace.trace(
            source=source,
            destination=destination,
            protocol=protocol,
            service=service,
            router=router,
            vrf=vrf,
            route_destination=route_destination or destination
        )
        return trace
     

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

    def _load_firewall_routes(self):
        file = Path("output/firewall_routes.json")

        if not file.exists():
            return []

        with open(file, encoding="utf-8") as f:
            rows = json.load(f)

        routes = []

        for r in rows:
            
                route = RouteEntry(
                    router=r.get("router") or r.get("device"),
                    vrf=r.get("vrf") or r.get("context") or "global",
                    prefix=r["prefix"],
                    next_hop=r["next_hop"],
                    protocol=r.get("protocol", "static")
                )

                route.interface = r.get("interface") or r.get("egress_interface")
                route.egress_interface = r.get("egress_interface") or r.get("interface")
                route.ingress_interface = r.get("ingress_interface")

                routes.append(route)
            

        return routes

    def _load_firewall_interfaces(self):
        file = Path("output/firewall_interfaces.json")

        if not file.exists():
            return []

        with open(file, encoding="utf-8") as f:
            return json.load(f)

    def _evaluate_trace_security(
        self,
        trace,
        source,
        destination,
        protocol=None,
        service=None
    ):
        if trace is None:
            return None

        firewall_hops = [
            hop
            for hop in getattr(trace, "network_hops", [])
            if getattr(hop, "hop_type", None) == "firewall"
        ]

        last_firewall = (
            firewall_hops[-1]
            if firewall_hops
            else None
        )

        acl_permitted = None

        if last_firewall is not None:
            policy = getattr(last_firewall, "policy", None)

            if policy == "permit":
                acl_permitted = True
            elif policy == "deny":
                acl_permitted = False

        security = getattr(trace, "security", None)

        acl_rule = None
        security_reason = None

        if security is not None:
            security_reason = getattr(security, "reason", None)

            rule = getattr(security, "rule", None)

            if rule is not None:
                acl_rule = getattr(rule, "name", None)

        security_context = SecurityContext(
            source=source,
            destination=destination,
            protocol=protocol,
            service=service,
            
            trace_status=getattr(trace, "status", None),

            acl_rule=acl_rule,
            security_reason=security_reason,

            egress_device=(
                getattr(last_firewall, "device", None)
                if last_firewall
                else None
            ),

            egress_interface=(
                getattr(last_firewall, "egress_interface", None)
                if last_firewall
                else None
            ),

            next_hop=(
                getattr(last_firewall, "next_hop", None)
                if last_firewall
                else None
            ),

            firewall_traversed=bool(firewall_hops),

            acl_permitted=acl_permitted,

            nat_evaluated=bool(
                last_firewall
                and getattr(last_firewall, "nat_rule", None)
            ),

            inventory_boundary=(
                getattr(trace, "status", None)
                == "inventory_boundary"
            ),

            forwarding_complete=bool(
                getattr(trace, "status", None)
                == "inventory_boundary"
                and last_firewall
                and getattr(
                    last_firewall,
                    "egress_interface",
                    None
                )
                and getattr(
                    last_firewall,
                    "next_hop",
                    None
                )
            )
        )

        return self.security.evaluate_context(
            security_context
        )

    def _load_nat_rules(self):

        file = Path("output/nat_rules.json")

        if not file.exists():
            return []

        with open(file, encoding="utf-8") as f:
            rows = json.load(f)

        rules = []

        from models.nat_rule import NATRule

        for row in rows:
            rules.append(
                NATRule(
                    name=row.get("name"),
                    context=row.get("context"),
                    source_original=row.get("source_original"),
                    source_translated=row.get("source_translated"),
                    destination_original=row.get("destination_original"),
                    destination_translated=row.get("destination_translated"),
                    service_original=row.get("service_original"),
                    service_translated=row.get("service_translated"),
                    direction=row.get("direction"),
                    section=row.get("section"),
                    reason=row.get("reason"),
                    raw=row.get("raw")
                )
            )

        return rules

    def trace_flow(
        self,
        source,
        destination,
        protocol=None,
        service=None,
        start=None
    ):

        return self.flow_trace_engine.trace(
            source,
            destination,
            protocol=protocol,
            service=service,
            start=start
        )

    def analyze_impact(
        self,
        source,
        destination,
        protocol=None,
        service=None,
        start=None
    ):

        trace = self.trace_flow(
            source,
            destination,
            protocol=protocol,
            service=service,
            start=start
        )

        return self.impact.analyze(
            trace=trace,
            source=source,
            destination=destination,
            protocol=protocol,
            service=service
        )