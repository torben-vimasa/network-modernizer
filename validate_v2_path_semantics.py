import json
from pathlib import Path

from api.digital_twin import DigitalTwin


PILOT_FILE = Path(
    "pilots/pilot_flows_combined.json"
)


def main():

    twin = DigitalTwin()

    pilots = json.loads(
        PILOT_FILE.read_text(
            encoding="utf-8"
        )
    )

    failures = []
    warnings = []

    for index, pilot in enumerate(
        pilots,
        start=1
    ):

        source = pilot.get(
            "source"
        )

        destination = pilot.get(
            "destination"
        )

        name = pilot.get(
            "name",
            f"{source} -> {destination}"
        )

        start = pilot.get(
            "start"
        )

        v2_start = None

        if start:

            resolution = (
                twin.trace.resolver.resolve_start(
                    start=start,
                    source_ip=source
                )
            )

            if not resolution.get(
                "resolved"
            ):
                failures.append(
                    (
                        index,
                        name,
                        "explicit start unresolved"
                    )
                )
                continue

            v2_start = {
                "device": resolution.get(
                    "device"
                ),
                "scope": (
                    resolution.get(
                        "context"
                    )
                    or resolution.get(
                        "vrf"
                    )
                ),
                "interface": resolution.get(
                    "interface"
                ),
                "ip": resolution.get(
                    "ip"
                )
            }

        result = twin.trace_flow(
            source,
            destination,
            start=v2_start
        )

        paths = result.get(
            "paths",
            []
        )

        selected = result.get(
            "selected_candidate"
        )

        selection_reason = result.get(
            "selection_reason"
        )

        #
        # selected_candidate must point to
        # a real path.
        #
        if selected is not None:

            if (
                selected < 1
                or selected > len(paths)
            ):
                failures.append(
                    (
                        index,
                        name,
                        "selected_candidate out of range"
                    )
                )

            elif not selection_reason:

                warnings.append(
                    (
                        index,
                        name,
                        "selected_candidate has no selection_reason"
                    )
                )

        #
        # Validate each path.
        #
        for path_index, path in enumerate(
            paths,
            start=1
        ):

            hops = path.get(
                "hops",
                []
            )

            device_path = path.get(
                "device_path"
            )

            logical_path = path.get(
                "logical_path"
            )

            if device_path is None:

                failures.append(
                    (
                        index,
                        name,
                        f"path {path_index} missing device_path"
                    )
                )

            if logical_path is None:

                failures.append(
                    (
                        index,
                        name,
                        f"path {path_index} missing logical_path"
                    )
                )

            if (
                logical_path is not None
                and len(logical_path) > len(hops)
            ):
                failures.append(
                    (
                        index,
                        name,
                        f"path {path_index} logical_path longer than hops"
                    )
                )

            gateway_role = path.get(
                "gateway_role"
            )

            hsrp_vip = path.get(
                "hsrp_virtual_ip"
            )

            hsrp_priority = path.get(
                "hsrp_priority"
            )

            if gateway_role:

                if not hsrp_vip:

                    failures.append(
                        (
                            index,
                            name,
                            f"path {path_index} gateway_role without HSRP VIP"
                        )
                    )

                if hsrp_priority is None:

                    failures.append(
                        (
                            index,
                            name,
                            f"path {path_index} gateway_role without HSRP priority"
                        )
                    )

        #
        # If multiple successful HSRP paths exist
        # and exactly one is preferred, it should
        # be selected.
        #
        successful_paths = [
            path
            for path in paths
            if path.get(
                "destination_reached"
            )
        ]

        preferred_successful = [
            i
            for i, path in enumerate(
                paths,
                start=1
            )
            if (
                path.get(
                    "destination_reached"
                )
                and path.get(
                    "gateway_role"
                )
                == "preferred_candidate"
            )
        ]

        if len(
            preferred_successful
        ) == 1:

            expected = (
                preferred_successful[0]
            )

            if selected != expected:

                failures.append(
                    (
                        index,
                        name,
                        (
                            f"preferred path {expected} "
                            f"not selected "
                            f"(selected={selected})"
                        )
                    )
                )

        #
        # A result claiming destination reached
        # must have at least one successful path.
        #
        if result.get(
            "destination_reached"
        ) and not successful_paths:

            failures.append(
                (
                    index,
                    name,
                    "top-level destination_reached without successful path"
                )
            )

    print()
    print("=" * 100)
    print("V2 PATH SEMANTIC VALIDATION")
    print("=" * 100)

    print(
        "Pilots:",
        len(pilots)
    )

    print(
        "Failures:",
        len(failures)
    )

    print(
        "Warnings:",
        len(warnings)
    )

    if failures:

        print()
        print("FAILURES")

        for item in failures:
            print(
                f"{item[0]:02}. "
                f"{item[1]} - "
                f"{item[2]}"
            )

    if warnings:

        print()
        print("WARNINGS")

        for item in warnings:
            print(
                f"{item[0]:02}. "
                f"{item[1]} - "
                f"{item[2]}"
            )


if __name__ == "__main__":
    main()