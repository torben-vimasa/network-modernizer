class TraversalEngineFactory:

    def __init__(self, twin):
        self.twin = twin

    def get_engine(self, device_type):

        normalized = (device_type or "").lower()

        if normalized == "router":
            return "router"

        if normalized == "firewall":
            return "firewall"

        return None