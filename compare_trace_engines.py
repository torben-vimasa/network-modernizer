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


def devices_equivalent(
    twin,
    workflow_device,
    v2_device
):

    if workflow_device == v2_device:
        return True

    #
    # Legacy TraceWorkflow may represent a firewall hop
    # using the physical firewall/chassis, while V2 may
    # represent the same hop using the ASA context.
    #
    firewall_node = twin.graph.find(
        "Firewall",
        workflow_device
    )

    context_node = twin.graph.find(
        "Context",
        v2_device
    )

    if (
        firewall_node
        and context_node
    ):

        for relation, node in twin.graph.neighbors(
            firewall_node.id
        ):

            if (
                relation == "HAS_CONTEXT"
                and node.id == context_node.id
            ):
                return True

    #
    # Also support the reverse direction.
    #
    firewall_node = twin.graph.find(
        "Firewall",
        v2_device
    )

    context_node = twin.graph.find(
        "Context",
        workflow_device
    )

    if (
        firewall_node
        and context_node
    ):

        for relation, node in twin.graph.neighbors(
            firewall_node.id
        ):

            if (
                relation == "HAS_CONTEXT"
                and node.id == context_node.id
            ):
                return True

    return False


def path_has_ordered_workflow(
    twin,
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

        position = 0

        for device in devices:

            if position >= len(
                workflow_devices_list
            ):
                break

            workflow_device = (
                workflow_devices_list[
                    position
                ]
            )

            if devices_equivalent(
                twin,
                workflow_device,
                device
            ):
                position += 1

        if position == len(
            workflow_devices_list
        ):
            return True

    return False


def path_has_exact_ordered_workflow(
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

        position = 0

        for device in devices:

            if (
                position < len(
                    workflow_devices_list
                )
                and device
                == workflow_devices_list[
                    position
                ]
            ):
                position += 1

        if position == len(
            workflow_devices_list
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

    forwarding_differences = 0
    representation_differences = 0

    #
    # Phase 4 security regression counters.
    #
    security_checked = 0
    security_differences = 0

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

        start = pilot.get(
            "start"
        )

        v2_start = None

        #
        # Resolve explicit ingress/start using the same
        # resolver as the legacy TraceWorkflow.
        #
        if start:

            start_resolution = (
                twin.trace.resolver.resolve_start(
                    start=start,
                    source_ip=source
                )
            )

            if start_resolution.get(
                "resolved"
            ):

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

            else:

                skipped += 1

                print(
                    "SKIPPED explicit start:",
                    name,
                    "-",
                    start_resolution.get(
                        "reason"
                    )
                )

                continue

        compared += 1

        #
        # ---------------------------------------------------------
        # LEGACY TRACE WORKFLOW
        # ---------------------------------------------------------
        #
        workflow = twin.trace.trace(
            source=source,
            destination=destination,
            protocol=pilot.get(
                "protocol"
            ),
            service=pilot.get(
                "service"
            ),
            start=start
        )

        #
        # ---------------------------------------------------------
        # FLOW TRACE V2
        # ---------------------------------------------------------
        #
        v2 = twin.trace_flow(
            source,
            destination,
            protocol=pilot.get(
                "protocol"
            ),
            service=pilot.get(
                "service"
            ),
            start=v2_start
        )

        #
        # ---------------------------------------------------------
        # FORWARDING COMPARISON
        # ---------------------------------------------------------
        #
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

        exact_ordered_path = (
            path_has_exact_ordered_workflow(
                w_devices,
                v_paths
            )
        )

        equivalent_ordered_path = (
            path_has_ordered_workflow(
                twin,
                w_devices,
                v_paths
            )
        )

        forwarding_difference = (
            not same_reachability
            or not equivalent_ordered_path
        )

        representation_difference = (
            same_reachability
            and equivalent_ordered_path
            and not exact_ordered_path
        )

        #
        # ---------------------------------------------------------
        # PHASE 4 SECURITY REGRESSION
        # ---------------------------------------------------------
        #
        # Security regression is intentionally opt-in.
        #
        # Existing pilots remain forwarding-only unless they
        # contain an "expected_security" object.
        #
        expected_security = (
            pilot.get(
                "expected_security"
            )
        )

        actual_security = (
            v2.get(
                "security_assessment"
            )
            or {}
        )

        security_difference = False
        security_match = None

        if expected_security is not None:

            security_checked += 1

            expected_disposition = (
                expected_security.get(
                    "disposition"
                )
            )

            expected_classification = (
                expected_security.get(
                    "classification"
                )
            )

            actual_disposition = (
                actual_security.get(
                    "disposition"
                )
            )

            actual_classification = (
                actual_security.get(
                    "classification"
                )
            )

            #
            # An omitted expected value acts as a wildcard.
            #
            disposition_match = (
                expected_disposition is None
                or expected_disposition
                == actual_disposition
            )

            classification_match = (
                expected_classification is None
                or expected_classification
                == actual_classification
            )

            security_match = (
                disposition_match
                and classification_match
            )

            security_difference = (
                not security_match
            )

        #
        # Nothing interesting to report.
        #
        if (
            not forwarding_difference
            and not representation_difference
            and not security_difference
        ):
            continue

        if forwarding_difference:
            forwarding_differences += 1

        if representation_difference:
            representation_differences += 1

        if security_difference:
            security_differences += 1

        #
        # ---------------------------------------------------------
        # DIFFERENCE REPORT
        # ---------------------------------------------------------
        #
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

        if start:

            output.append(
                f"EXPLICIT START : {start}"
            )

            output.append(
                f"V2 START       : {v2_start}"
            )

            output.append("")

        #
        # Legacy result.
        #
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

        #
        # V2 result.
        #
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

        #
        # Phase 4 top-level security semantics.
        #
        output.append(
            f"  security           : "
            f"{actual_security.get('disposition')}"
        )

        output.append(
            f"  classification     : "
            f"{actual_security.get('classification')}"
        )

        output.append(
            f"  security confidence: "
            f"{actual_security.get('confidence')}"
        )

        output.append("")

        #
        # Candidate paths.
        #
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

        #
        # Comparison.
        #
        output.append(
            "COMPARISON"
        )

        output.append(
            f"  same reachability        : "
            f"{same_reachability}"
        )

        output.append(
            f"  exact ordered path       : "
            f"{exact_ordered_path}"
        )

        output.append(
            f"  equivalent ordered path  : "
            f"{equivalent_ordered_path}"
        )

        output.append(
            f"  forwarding difference    : "
            f"{forwarding_difference}"
        )

        output.append(
            f"  representation difference: "
            f"{representation_difference}"
        )

        output.append(
            f"  security checked         : "
            f"{expected_security is not None}"
        )

        output.append(
            f"  security match           : "
            f"{security_match}"
        )

        output.append(
            f"  security difference      : "
            f"{security_difference}"
        )

        if expected_security is not None:

            output.append(
                f"  expected disposition     : "
                f"{expected_security.get('disposition')}"
            )

            output.append(
                f"  actual disposition       : "
                f"{actual_security.get('disposition')}"
            )

            output.append(
                f"  expected classification  : "
                f"{expected_security.get('classification')}"
            )

            output.append(
                f"  actual classification    : "
                f"{actual_security.get('classification')}"
            )

        output.append("")

    #
    # -------------------------------------------------------------
    # SUMMARY
    # -------------------------------------------------------------
    #
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
        f"Pilots total              : {len(pilots)}"
    )

    output.append(
        f"Compared                  : {compared}"
    )

    output.append(
        f"Skipped                   : {skipped}"
    )

    output.append(
        f"Forwarding differences    : "
        f"{forwarding_differences}"
    )

    output.append(
        f"Representation differences: "
        f"{representation_differences}"
    )

    output.append(
        f"Security pilots checked   : "
        f"{security_checked}"
    )

    output.append(
        f"Security differences      : "
        f"{security_differences}"
    )

    #
    # Write comparison report.
    #
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
        "Forwarding differences:",
        forwarding_differences
    )

    print(
        "Representation differences:",
        representation_differences
    )

    print(
        "Security pilots checked:",
        security_checked
    )

    print(
        "Security differences:",
        security_differences
    )


if __name__ == "__main__":
    main()