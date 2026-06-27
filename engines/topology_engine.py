import json
from pathlib import Path


class TopologyEngine:

    def __init__(self, routes_file=Path("output/routes.json")):

        with open(routes_file, "r") as f:
            self.routes = json.load(f)

    def resolve_router(self, next_hop):

        for route in self.routes:

            if route["next_hop"] == next_hop:
                return {
                    "router": route["router"],
                    "vrf": route["vrf"]
                }

        return None