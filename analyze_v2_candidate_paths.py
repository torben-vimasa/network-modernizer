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

    multi_path = []

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

            start_resolution = (
                twin.trace.resolver.resolve_start(
                    start=start,
                    source_ip=source
                )
            )

            if not start_resolution.get(
                "resolved"
            ):
                print(
                    "SKIPPED:",
                    name,
                    "-",
                    start_resolution.get(
                        "reason"
                    )
                )
                continue

            v2_start = {
                "device": (
                    start_resolution.get(
                        "device"
                    )
                ),
                "scope": (
                    start_resolution.get(
                        "context"
                    )
                    or start_resolution.get(
                        "vrf"
                    )
                ),
                "interface": (
                    start_resolution.get(
                        "interface"
                    )
                ),
                "ip": (
                    start_resolution.get(
                        "ip"
                    )
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

        if len(paths) <= 1:
            continue

        multi_path.append(
            (
                index,
                name,
                source,
                destination,
                paths
            )
        )

    print()
    print("=" * 100)
    print("MULTI-PATH PILOTS")
    print("=" * 100)

    for (
        index,
        name,
        source,
        destination,
        paths
    ) in multi_path:

        print()
        print(
            f"{index:02}. {name}"
        )

        print(
            f"{source} -> {destination}"
        )

        print(
            f"Candidate paths: {len(paths)}"
        )

        for path_index, path in enumerate(
            paths,
            start=1
        ):

            devices = []

            for hop in path.get(
                "hops",
                []
            ):

                device = hop.get(
                    "device"
                )

                if (
                    device
                    and device not in devices
                ):
                    devices.append(
                        device
                    )

                forwarding = (
                    hop.get(
                        "forwarding"
                    )
                    or {}
                )

                next_device = (
                    forwarding.get(
                        "device"
                    )
                )

                if (
                    next_device
                    and next_device not in devices
                ):
                    devices.append(
                        next_device
                    )

            print(
                f"  PATH {path_index}"
            )

            print(
                f"    reached  : "
                f"{path.get('destination_reached')}"
            )

            print(
                f"    boundary : "
                f"{path.get('inventory_boundary')}"
            )

            print(
                f"    gateway  : "
                f"{path.get('gateway_role')}"
            )

            print(
                f"    hsrp vip : "
                f"{path.get('hsrp_virtual_ip')}"
            )

            print(
                f"    priority : "
                f"{path.get('hsrp_priority')}"
            )

            print(
                f"    devices  : "
                f"{devices}"
            )

            print(
                f"    reason   : "
                f"{path.get('reason')}"
            )

    print()
    print("=" * 100)
    print(
        f"Pilots with >1 V2 path: "
        f"{len(multi_path)}"
    )
    print("=" * 100)


if __name__ == "__main__":
    main()