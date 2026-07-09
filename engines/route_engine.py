import ipaddress
import json
from pathlib import Path

from models.route_explanation import RouteExplanation
from models.confidence import Confidence



class RouteEngine:

    def __init__(self):

        self.routes = []

        #
        # Static routes
        #
        self.routes.extend(
            self._load_routes(
                Path("output/routes.json")
            )
        )

        #
        # Runtime routing table (optional)
        #
        runtime = Path("output/routes_runtime.json")

        if runtime.exists():

            self.routes.extend(
                self._load_routes(runtime)
            )

        self._normalize_routes()


    def _normalize_routes(self):

        ADMIN_DISTANCE = {
            "connected": 0,
            "local": 0,
            "static": 1,
            "ebgp": 20,
            "bgp": 20,
            "eigrp": 90,
            "ospf": 110,
            "rip": 120,
            "ibgp": 200,
        }

        for route in self.routes:

            protocol = str(
                route.get("protocol", "")
            ).lower()

            route["admin_distance"] = ADMIN_DISTANCE.get(
                protocol,
                255
            )

            if route.get("metric") is None:
                route["metric"] = 0



    def _load_routes(self, file):

        if not file.exists():
            return []

        with open(file, encoding="utf-8") as f:
            return json.load(f)

    def lookup(self, router, vrf, destination):
        destination_ip = ipaddress.ip_address(destination)
        matches = []

        for route in self.routes:
            if route["router"] != router:
                continue

            if route["vrf"] != vrf:
                continue

            try:
                network = ipaddress.ip_network(route["prefix"], strict=False)
            except ValueError:
                continue

            if destination_ip in network:
                matches.append((network.prefixlen, route))

        if not matches:
            return None

        matches.sort(
            key=lambda item: (
                -item[0],                          # længste prefix
                item[1]["admin_distance"],         # laveste AD
                item[1]["metric"]                  # laveste metric
            )
        )

    def explain(self, router, vrf, destination):

        route = self.lookup(router, vrf, destination)

        if not route:
            return None

        return RouteExplanation(
            destination=destination,
            matched_prefix=route["prefix"],
            reason="Longest prefix match",
            protocol=route["protocol"],
            next_hop=route["next_hop"],
            confidence=Confidence(
                level="high",
                score=1.0,
                reason="Static route parsed directly from router configuration"
            )
        )