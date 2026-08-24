from models.change_analysis_result import ChangeAnalysisResult


class ChangeAnalysisEngine:

    def __init__(self):
        pass

    def analyze(
        self,
        current_impact,
        change
    ):

        primary_devices = set(
            current_impact.affected_devices
        )

        candidate_devices = set(
            current_impact.candidate_devices
        )

        primary_vrfs = set(
            current_impact.affected_vrfs
        )

        candidate_vrfs = set(
            current_impact.candidate_vrfs
        )

        primary_routes = list(
            current_impact.primary_routes
        )

        candidate_routes = list(
            current_impact.candidate_routes
        )

        change_touches_primary_path = False
        change_touches_candidate_path = False

        affected_devices = []
        affected_vrfs = []

        #
        # ---------------------------------------------------------
        # DEVICE IMPACT
        # ---------------------------------------------------------
        #
        if change.device:

            if change.device in primary_devices:
                change_touches_primary_path = True

            if change.device in candidate_devices:
                change_touches_candidate_path = True

            if change.device in candidate_devices:

                affected_devices.append(
                    change.device
                )

        #
        # ---------------------------------------------------------
        # SCOPE / VRF IMPACT
        # ---------------------------------------------------------
        #
        if change.scope:

            if change.scope in primary_vrfs:
                change_touches_primary_path = True

            if change.scope in candidate_vrfs:
                change_touches_candidate_path = True

            if change.scope in candidate_vrfs:

                affected_vrfs.append(
                    change.scope
                )

        #
        # ---------------------------------------------------------
        # ROUTE-SPECIFIC IMPACT
        # ---------------------------------------------------------
        #
        primary_route_matches = (
            self._matching_routes(
                primary_routes,
                change
            )
        )

        candidate_route_matches = (
            self._matching_routes(
                candidate_routes,
                change
            )
        )

        if primary_route_matches:
            change_touches_primary_path = True

        if candidate_route_matches:
            change_touches_candidate_path = True

        #
        # ---------------------------------------------------------
        # SEMANTIC ASSESSMENT
        # ---------------------------------------------------------
        #
        if primary_route_matches:

            assessment = (
                "The proposed change matches a route "
                "used by the current primary forwarding path."
            )

            confidence = "high"

        elif change_touches_primary_path:

            assessment = (
                "The proposed change touches the "
                "current primary forwarding path."
            )

            confidence = "high"

        elif candidate_route_matches:

            assessment = (
                "The proposed change matches a route "
                "used by an alternative candidate path."
            )

            confidence = "high"

        elif change_touches_candidate_path:

            assessment = (
                "The proposed change does not touch "
                "the current primary path, but it "
                "touches an alternative candidate path."
            )

            confidence = "high"

        else:

            assessment = (
                "The proposed change does not touch "
                "the currently resolved primary or "
                "candidate forwarding paths."
            )

            confidence = "medium"

        #
        # ---------------------------------------------------------
        # RESULT
        # ---------------------------------------------------------
        #
        return ChangeAnalysisResult(
            source=current_impact.source,
            destination=current_impact.destination,

            change=change,

            current_impact=current_impact,

            change_touches_primary_path=(
                change_touches_primary_path
            ),

            change_touches_candidate_path=(
                change_touches_candidate_path
            ),

            affected_devices=(
                affected_devices
            ),

            affected_vrfs=(
                affected_vrfs
            ),

            primary_route_matches=(
                primary_route_matches
            ),

            candidate_route_matches=(
                candidate_route_matches
            ),

            assessment=assessment,

            confidence=confidence
        )

    def _matching_routes(
        self,
        routes,
        change
    ):

        matches = []

        for route in routes:

            #
            # Device selector.
            #
            if (
                change.device
                and route.get(
                    "device"
                ) != change.device
            ):
                continue

            #
            # Scope / VRF selector.
            #
            if (
                change.scope
                and route.get(
                    "scope"
                ) != change.scope
            ):
                continue

            #
            # Prefix selector.
            #
            if (
                change.prefix
                and route.get(
                    "prefix"
                ) != change.prefix
            ):
                continue

            #
            # Existing next-hop selector.
            #
            if (
                change.current_next_hop
                and route.get(
                    "next_hop"
                ) != change.current_next_hop
            ):
                continue

            #
            # Existing egress-interface selector.
            #
            if (
                change.current_interface
                and route.get(
                    "egress_interface"
                ) != change.current_interface
            ):
                continue

            #
            # Device/scope alone are useful for general
            # impact detection, but they are not sufficient
            # to claim an exact route match.
            #
            if not any([
                change.prefix,
                change.current_next_hop,
                change.current_interface
            ]):
                continue

            matches.append(
                route
            )

        return matches