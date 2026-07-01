from engines.firewall_traversal_engine import FirewallTraversalEngine
from engines.router_traversal_engine import RouterTraversalEngine


class TraversalEngineFactory:

    def __init__(self, twin):
        self.twin = twin

    def get_engine(self, device_type):

        normalized = (device_type or "").lower()

        if normalized == "router":
            return RouterTraversalEngine(self.twin)

        if normalized == "firewall":
            return FirewallTraversalEngine(self.twin)

        return None