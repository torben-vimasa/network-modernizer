from models.impact_result import ImpactResult


class ImpactEngine:

    def __init__(self):
        pass

    def analyze(
        self,
        trace,
        source,
        destination,
        protocol=None,
        service=None
    ):

        if not trace:

            return ImpactResult(
                source=source,
                destination=destination,
                protocol=protocol,
                service=service,
                reason="No trace result available."
            )

        paths = trace.get(
            "paths",
            []
        )

        selected_candidate = trace.get(
            "selected_candidate"
        )

        security = (
            trace.get(
                "security_assessment"
            )
            or {}
        )

        #
        # ---------------------------------------------------------
        # ALL CANDIDATE PATHS
        # ---------------------------------------------------------
        #
        candidate_devices = []
        candidate_firewalls = []
        candidate_routers = []
        candidate_vrfs = []
        candidate_routes = []

        for path in paths:

            self._extend_unique(
                candidate_devices,
                self._path_devices(
                    path
                )
            )

            self._extend_unique(
                candidate_firewalls,
                path.get(
                    "firewalls",
                    []
                )
            )

            self._extend_unique(
                candidate_routers,
                path.get(
                    "routers",
                    []
                )
            )

            self._extend_unique(
                candidate_vrfs,
                path.get(
                    "vrfs",
                    []
                )
            )

            self._extend_unique(
                candidate_routes,
                self._path_routes(
                    path
                )
            )

        #
        # ---------------------------------------------------------
        # PRIMARY / SELECTED PATH
        # ---------------------------------------------------------
        #
        primary_path = None
        primary_path_index = None

        if (
            selected_candidate
            and 1 <= selected_candidate <= len(paths)
        ):

            primary_path_index = (
                selected_candidate
            )

            primary_path = paths[
                selected_candidate - 1
            ]

        #
        # If no deterministic candidate was selected:
        #
        # 1. use first successful path
        # 2. otherwise first available path
        #
        if primary_path is None:

            for index, path in enumerate(
                paths,
                start=1
            ):

                if path.get(
                    "destination_reached"
                ):

                    primary_path = path
                    primary_path_index = index
                    break

        if (
            primary_path is None
            and paths
        ):

            primary_path = paths[0]
            primary_path_index = 1

        #
        # Primary impact collections.
        #
        affected_devices = []
        affected_firewalls = []
        affected_routers = []
        affected_vrfs = []
        primary_routes = []

        if primary_path:

            affected_devices = (
                self._path_devices(
                    primary_path
                )
            )

            affected_firewalls = list(
                primary_path.get(
                    "firewalls",
                    []
                )
            )

            affected_routers = list(
                primary_path.get(
                    "routers",
                    []
                )
            )

            affected_vrfs = list(
                primary_path.get(
                    "vrfs",
                    []
                )
            )

            primary_routes = (
                self._path_routes(
                    primary_path
                )
            )

        #
        # ---------------------------------------------------------
        # RESULT
        # ---------------------------------------------------------
        #
        return ImpactResult(
            source=source,
            destination=destination,
            protocol=protocol,
            service=service,

            path_resolved=bool(
                trace.get(
                    "path_resolved"
                )
            ),

            destination_reached=bool(
                trace.get(
                    "destination_reached"
                )
            ),

            inventory_boundary=bool(
                trace.get(
                    "inventory_boundary"
                )
            ),

            selected_candidate=(
                selected_candidate
            ),

            primary_path_index=(
                primary_path_index
            ),

            candidate_path_count=len(
                paths
            ),

            #
            # Primary impact.
            #
            affected_devices=(
                affected_devices
            ),

            affected_firewalls=(
                affected_firewalls
            ),

            affected_routers=(
                affected_routers
            ),

            affected_vrfs=(
                affected_vrfs
            ),

            primary_routes=(
                primary_routes
            ),

            #
            # Candidate / potential impact.
            #
            candidate_devices=(
                candidate_devices
            ),

            candidate_firewalls=(
                candidate_firewalls
            ),

            candidate_routers=(
                candidate_routers
            ),

            candidate_vrfs=(
                candidate_vrfs
            ),

            candidate_routes=(
                candidate_routes
            ),

            #
            # Security semantics inherited from Flow Trace V2.
            #
            security_disposition=(
                security.get(
                    "disposition"
                )
            ),

            security_classification=(
                security.get(
                    "classification"
                )
            ),

            security_confidence=(
                security.get(
                    "confidence"
                )
            ),

            confidence=trace.get(
                "confidence"
            ),

            reason=trace.get(
                "reason"
            )
        )

    def _path_devices(
        self,
        path
    ):

        devices = []

        for item in path.get(
            "logical_path",
            []
        ):

            device = item.get(
                "device"
            )

            if (
                device
                and device not in devices
            ):

                devices.append(
                    device
                )

        return devices

    def _path_routes(
        self,
        path
    ):

        routes = []

        for hop in path.get(
            "hops",
            []
        ):

            route = (
                hop.get(
                    "route"
                )
                or {}
            )

            if not route:
                continue

            forwarding = (
                hop.get(
                    "forwarding"
                )
                or {}
            )

            route_item = {
                "device": (
                    hop.get(
                        "device"
                    )
                ),

                "scope": (
                    hop.get(
                        "vrf"
                    )
                ),

                "prefix": (
                    route.get(
                        "prefix"
                    )
                ),

                "protocol": (
                    route.get(
                        "protocol"
                    )
                ),

                "next_hop": (
                    route.get(
                        "next_hop"
                    )
                ),

                "egress_interface": (
                    hop.get(
                        "egress_interface"
                    )
                    or forwarding.get(
                        "interface"
                    )
                )
            }

            if route_item not in routes:

                routes.append(
                    route_item
                )

        return routes

    def _extend_unique(
        self,
        target,
        values
    ):

        for value in values:

            if (
                value
                and value not in target
            ):

                target.append(
                    value
                )