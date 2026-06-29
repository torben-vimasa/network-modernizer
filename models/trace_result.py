class TraceResult:

    def __init__(
        self,
        security=None,
        route=None,
        hops=None,
        firewall_hops=None,
        network_hops=None,
        explanation=None
    ):
        self.security = security
        self.route = route
        self.hops = hops or []
        self.firewall_hops = firewall_hops or []
        self.network_hops = network_hops or []
        self.explanation = explanation