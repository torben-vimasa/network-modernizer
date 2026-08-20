import json
from pathlib import Path

from api.digital_twin import DigitalTwin


PILOT_FILE = Path(
    "pilots/pilot_flows_combined.json"
)

OUTPUT_FILE = Path(
    "output/trace_engine_comparison.txt"
)


def workflow_devices(result):

    devices = []

    for hop in getattr(
        result,
        "network_hops",
        []
    ) or []:

        device = getattr(
            hop,
            "device",
            None
        )

        if (
            device
            and device not in devices
        ):
            devices.append(device)

    return devices


def workflow_reached(result):

    status = str(
        getattr(
            result,
            "status",
            ""
        )
        or ""
    ).lower()

    if status == "reachable":
        return True

    explanation = getattr(
        result,
        "explanation",
        None
    )

    if explanation:

        steps = getattr(
            explanation,
            "steps",
            []
        ) or []

        text = "\n".join(
            str(step)
            for step in steps
        ).lower()

        if (
            "destination reached" in text
            or "result: reachable" in text
        ):
            return True

    return False


def v2_paths(result):

    paths = []

    for path in result.get(
        "paths",
        []
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
                devices.append(device)

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

        paths.append({
            "devices": devices,
            "destination_reached": bool(
                path.get(
                    "destination_reached",
                    False
                )
            ),
            "inventory_boundary": bool(
                path.get(
                    "inventory_boundary",
                    False
                )
            ),
            "reason": path.get(
                "reason"
            )
        })

    return paths


def v2_all_devices(paths):

    devices = []

    for path in paths:

        for device in path.get(
            "devices",
            []
        ):

            if device not in devices:
                devices.append(device)

    return devices


def path_has_common_device(
    workflow_devices_list,
    v2_path_list
):

    if not workflow_devices_list:
        return True

    for path in v2_path_list:

        devices = path.get(
            "devices",
            []
        )

        if any(
            device in devices
            for device in workflow_devices_list
        ):
            return True

    return False


def main():

    twin = DigitalTwin()

    pilots = json.loads(
        PILOT_FILE.read_text(
            encoding="utf-8"
        )
    )

    output = []

    differences = 0
    compared = 0
    skipped = 0

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

        if pilot.get("start"):

            skipped += 1
            continue

        compared += 1

        workflow = twin.trace.trace(
            source=source,
            destination=destination,
            protocol=pilot.get(
                "protocol"
            ),
            service=pilot.get(
                "service"
            )
        )

        v2 = twin.trace_flow(
            source,
            destination
        )

        w_reached = workflow_reached(
            workflow
        )

        v_reached = bool(
            v2.get(
                "destination_reached"
            )
        )

        w_devices = workflow_devices(
            workflow
        )

        v_paths = v2_paths(
            v2
        )

        v_devices = v2_all_devices(
            v_paths
        )

        same_reachability = (
            w_reached == v_reached
        )

        common_path = (
            path_has_common_device(
                w_devices,
                v_paths
            )
        )

        differing = (
            not same_reachability
            or not common_path
        )

        if not differing:
            continue

        differences += 1

        output.append(
            "=" * 100
        )

        output.append(
            f"{index:02}. {name}"
        )

        output.append(
            f"{source} -> {destination}"
        )

        output.append("")

        output.append(
            "TRACE WORKFLOW"
        )

        output.append(
            f"  status  : "
            f"{getattr(workflow, 'status', None)}"
        )

        output.append(
            f"  reached : {w_reached}"
        )

        output.append(
            f"  devices : {w_devices}"
        )

        output.append(
            f"  reason  : "
            f"{getattr(workflow, 'reason', None)}"
        )

        output.append("")

        output.append(
            "FLOW TRACE V2"
        )

        output.append(
            f"  reached            : "
            f"{v_reached}"
        )

        output.append(
            f"  inventory_boundary : "
            f"{v2.get('inventory_boundary')}"
        )

        output.append(
            f"  confidence         : "
            f"{v2.get('confidence')}"
        )

        output.append(
            f"  candidate paths    : "
            f"{len(v_paths)}"
        )

        output.append(
            f"  all devices        : "
            f"{v_devices}"
        )

        output.append(
            f"  reason             : "
            f"{v2.get('reason')}"
        )

        output.append("")

        for path_index, path in enumerate(
            v_paths,
            start=1
        ):

            output.append(
                f"    PATH {path_index}"
            )

            output.append(
                f"      reached  : "
                f"{path.get('destination_reached')}"
            )

            output.append(
                f"      boundary : "
                f"{path.get('inventory_boundary')}"
            )

            output.append(
                f"      devices  : "
                f"{path.get('devices')}"
            )

            output.append(
                f"      reason   : "
                f"{path.get('reason')}"
            )

        output.append("")

        output.append(
            "COMPARISON"
        )

        output.append(
            f"  same reachability : "
            f"{same_reachability}"
        )

        output.append(
            f"  common V2 path    : "
            f"{common_path}"
        )

        output.append("")

    output.append(
        "=" * 100
    )

    output.append(
        "SUMMARY"
    )

    output.append(
        "=" * 100
    )

    output.append(
        f"Pilots total : {len(pilots)}"
    )

    output.append(
        f"Compared     : {compared}"
    )

    output.append(
        f"Skipped      : {skipped}"
    )

    output.append(
        f"Differences  : {differences}"
    )

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    OUTPUT_FILE.write_text(
        "\n".join(output),
        encoding="utf-8"
    )

    print(
        "Written:",
        OUTPUT_FILE
    )

    print(
        "Compared:",
        compared
    )

    print(
        "Skipped:",
        skipped
    )

    print(
        "Differences:",
        differences
    )


if __name__ == "__main__":
    main()
