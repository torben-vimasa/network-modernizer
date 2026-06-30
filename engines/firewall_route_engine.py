from models.route_result import RouteResult


class FirewallRouteEngine:

    def __init__(self, routes):

        self.routes = routes

    def lookup(self, destination):

        #
        # Midlertidig version.
        #
        # I næste sprint bruger vi graph +
        # longest prefix ligesom RouteEngine.
        #

        for route in self.routes:

            if route.prefix == "0.0.0.0/0":

                return RouteResult(
                    matched=True,
                    hop=None
                )

        return RouteResult(
            matched=False,
            hop=None
        )