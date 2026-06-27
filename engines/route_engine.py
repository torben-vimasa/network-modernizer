import ipaddress
import json
from pathlib import Path


class RouteEngine:

    def __init__(self, routes_file=Path("output/routes.json")):
        with open(routes_file, "r") as f:
            self.routes = json.load(f)

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

        matches.sort(key=lambda item: item[0], reverse=True)
        return matches[0][1]