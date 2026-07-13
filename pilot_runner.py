import argparse
import json
import sys
from pathlib import Path
from typing import Any

from api.digital_twin import DigitalTwin


DEFAULT_PILOT_PATH = Path("pilots")


def load_pilot_files(path: Path) -> list[dict[str, Any]]:
    """
    Load pilot definitions from one JSON file or recursively from a directory.

    Supported JSON formats:

    1. A list:
       [
           {"name": "...", "source": "...", "destination": "..."}
       ]

    2. A single pilot object:
       {
           "name": "...",
           "source": "...",
           "destination": "..."
       }

    3. An object containing a flows list:
       {
           "flows": [...]
       }
    """

    if not path.exists():
        raise FileNotFoundError(
            f"Pilot path does not exist: {path}"
        )

    if path.is_file():
        files = [path]
    else:
        files = sorted(path.rglob("*.json"))

    pilots: list[dict[str, Any]] = []

    for file in files:
        with open(file, encoding="utf-8") as handle:
            content = json.load(handle)

        if isinstance(content, list):
            file_pilots = content

        elif isinstance(content, dict) and isinstance(
            content.get("flows"),
            list
        ):
            file_pilots = content["flows"]

        elif isinstance(content, dict):
            file_pilots = [content]

        else:
            raise ValueError(
                f"Unsupported JSON structure in {file}"
            )

        for index, pilot in enumerate(file_pilots, start=1):
            if not isinstance(pilot, dict):
                raise ValueError(
                    f"Pilot {index} in {file} is not an object"
                )

            loaded = dict(pilot)
            loaded["_pilot_file"] = str(file)
            loaded["_pilot_index"] = index

            pilots.append(loaded)

    return pilots


def normalize_pilot(
    pilot: dict[str, Any]
) -> dict[str, Any]:

    source = (
        pilot.get("source")
        or pilot.get("src")
    )

    destination = (
        pilot.get("destination")
        or pilot.get("dst")
    )

    if not source:
        raise ValueError(
            f"Pilot is missing source/src: "
            f"{pilot.get('_pilot_file')}"
        )

    if not destination:
        raise ValueError(
            f"Pilot is missing destination/dst: "
            f"{pilot.get('_pilot_file')}"
        )

    name = pilot.get("name") or (
        f"{source} to {destination}"
    )

    return {
        "name": name,
        "source": source,
        "destination": destination,
        "protocol": pilot.get("protocol"),
        "service": pilot.get("service"),
        "router": pilot.get("router"),
        "vrf": pilot.get("vrf"),
        "route_destination": pilot.get(
            "route_destination"
        ),
        "max_hops": pilot.get("max_hops", 20),
        "expected": pilot.get("expected", {}),
        "_pilot_file": pilot.get("_pilot_file"),
        "_pilot_index": pilot.get("_pilot_index")
    }


def run_trace(
    twin: DigitalTwin,
    pilot: dict[str, Any]
):
    kwargs = {
        "source": pilot["source"],
        "destination": pilot["destination"],
        "protocol": pilot.get("protocol"),
        "service": pilot.get("service"),
        "max_hops": pilot.get("max_hops", 20)
    }

    #
    # Backwards-compatible explicit start overrides.
    #
    if pilot.get("router"):
        kwargs["router"] = pilot["router"]

    if pilot.get("vrf"):
        kwargs["vrf"] = pilot["vrf"]

    if pilot.get("route_destination"):
        kwargs["route_destination"] = (
            pilot["route_destination"]
        )

    return twin.trace.trace(**kwargs)


def explanation_lines(result) -> list[str]:
    explanation = getattr(
        result,
        "explanation",
        None
    )

    if explanation is None:
        return []

    #
    # Explanation implementations may expose their
    # entries under different attributes.
    #
    for attribute in [
        "entries",
        "lines",
        "messages",
        "steps",
        "history"
    ]:
        value = getattr(
            explanation,
            attribute,
            None
        )

        if isinstance(value, list):
            return [
                str(item)
                for item in value
            ]

    #
    # Last-resort extraction from iterable objects.
    #
    try:
        if not isinstance(
            explanation,
            (str, bytes)
        ):
            return [
                str(item)
                for item in explanation
            ]
    except TypeError:
        pass

    return [str(explanation)]


def determine_status(result) -> str:
    """
    Convert the low-level TraceResult into a stable
    regression status.

    Status values:
      reachable
      denied
      no_route
      incomplete_data
      stopped
    """

    lines = explanation_lines(result)

    text = "\n".join(lines).lower()

    security = getattr(
        result,
        "security",
        None
    )

    if (
        security is not None
        and getattr(
            security,
            "permitted",
            None
        ) is False
    ):
        return "denied"

    network_hops = (
        getattr(
            result,
            "network_hops",
            None
        )
        or []
    )

    for hop in network_hops:
        if (
            getattr(
                hop,
                "policy",
                None
            ) == "deny"
        ):
            return "denied"

    if (
        "destination reached" in text
        or "result: reachable" in text
    ):
        return "reachable"

    if (
        "no route matched" in text
        or "no firewall route found" in text
    ):
        return "no_route"

    incomplete_markers = [
        "could not resolve source",
        "could not be directly resolved",
        "missing next-router inventory",
        "not found in graph",
        "no subnet found",
        "unresolved",
        "unsupported method"
    ]

    if any(
        marker in text
        for marker in incomplete_markers
    ):
        return "incomplete_data"

    return "stopped"


def collect_devices(result) -> list[str]:
    devices: list[str] = []

    for hop in (
        getattr(
            result,
            "network_hops",
            None
        )
        or []
    ):
        device = getattr(
            hop,
            "device",
            None
        )

        if device and device not in devices:
            devices.append(device)

    return devices


def collect_acl_rules(result) -> list[str]:
    rules: list[str] = []

    security = getattr(
        result,
        "security",
        None
    )

    if security is not None:
        rule = getattr(
            security,
            "rule",
            None
        )

        if rule is not None:
            rule_name = getattr(
                rule,
                "name",
                None
            )

            if rule_name:
                rules.append(str(rule_name))

        match = getattr(
            security,
            "match",
            None
        )

        if match is not None:
            acl = getattr(
                match,
                "acl",
                None
            )

            sequence = getattr(
                match,
                "rule",
                None
            )

            if acl and sequence is not None:
                value = f"{acl}:{sequence}"

                if value not in rules:
                    rules.append(value)

    for hop in (
        getattr(
            result,
            "network_hops",
            None
        )
        or []
    ):
        rule = getattr(
            hop,
            "acl_rule",
            None
        )

        if rule and str(rule) not in rules:
            rules.append(str(rule))

    return rules


def compare_ordered_subsequence(
    actual: list[str],
    expected: list[str]
) -> bool:
    """
    Expected devices do not have to describe every hop,
    but they must occur in the given order.
    """

    if not expected:
        return True

    position = 0

    for value in actual:
        if value == expected[position]:
            position += 1

            if position == len(expected):
                return True

    return False


def evaluate_expectations(
    pilot: dict[str, Any],
    result
) -> dict[str, Any]:

    expected = pilot.get("expected") or {}

    actual_status = determine_status(result)
    actual_devices = collect_devices(result)
    actual_acl_rules = collect_acl_rules(result)

    checks: list[dict[str, Any]] = []

    expected_status = expected.get("status")

    if expected_status:
        checks.append(
            {
                "name": "status",
                "passed": (
                    actual_status
                    == expected_status
                ),
                "expected": expected_status,
                "actual": actual_status
            }
        )

    expected_devices = (
        expected.get("devices")
        or expected.get("expected_devices")
        or []
    )

    if expected_devices:
        checks.append(
            {
                "name": "devices",
                "passed": compare_ordered_subsequence(
                    actual_devices,
                    expected_devices
                ),
                "expected": expected_devices,
                "actual": actual_devices
            }
        )

    expected_acl_rules = (
        expected.get("acl_rules")
        or expected.get("expected_rule_ids")
        or []
    )

    if expected_acl_rules:
        missing_rules = [
            rule
            for rule in expected_acl_rules
            if str(rule) not in actual_acl_rules
        ]

        checks.append(
            {
                "name": "acl_rules",
                "passed": not missing_rules,
                "expected": expected_acl_rules,
                "actual": actual_acl_rules
            }
        )

    #
    # A pilot without expectations is observational.
    # It is executed and reported but does not fail
    # the regression suite.
    #
    regression_passed = all(
        check["passed"]
        for check in checks
    )

    return {
        "status": actual_status,
        "devices": actual_devices,
        "acl_rules": actual_acl_rules,
        "checks": checks,
        "has_expectations": bool(checks),
        "passed": regression_passed
    }


def print_pilot_result(
    number: int,
    pilot: dict[str, Any],
    evaluation: dict[str, Any],
    verbose: bool
):

    if not evaluation["has_expectations"]:
        result_label = "OBSERVE"
    elif evaluation["passed"]:
        result_label = "PASS"
    else:
        result_label = "FAIL"

    print(
        f"{number:02d}. "
        f"{pilot['name']:<45} "
        f"{result_label}"
    )

    print(
        f"    {pilot['source']} -> "
        f"{pilot['destination']} "
        f"[{pilot.get('service') or pilot.get('protocol') or 'any'}]"
    )

    print(
        f"    Status : {evaluation['status']}"
    )

    if evaluation["devices"]:
        print(
            "    Path   : "
            + " -> ".join(
                evaluation["devices"]
            )
        )
    else:
        print("    Path   : none")

    if evaluation["acl_rules"]:
        print(
            "    ACL    : "
            + ", ".join(
                evaluation["acl_rules"]
            )
        )

    for check in evaluation["checks"]:

        marker = (
            "OK"
            if check["passed"]
            else "ERROR"
        )

        print(
            f"    [{marker}] "
            f"{check['name']}: "
            f"expected={check['expected']} "
            f"actual={check['actual']}"
        )

    if verbose:
        print(
            f"    File   : "
            f"{pilot.get('_pilot_file')}"
        )

    print()


def main() -> int:

    parser = argparse.ArgumentParser(
        description=(
            "Run NDT pilot flows as regression tests."
        )
    )

    parser.add_argument(
        "path",
        nargs="?",
        default=str(DEFAULT_PILOT_PATH),
        help=(
            "Pilot JSON file or directory. "
            "Default: pilots"
        )
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show pilot source file information."
    )

    parser.add_argument(
        "--fail-on-observe",
        action="store_true",
        help=(
            "Treat pilots without expected results "
            "as failures."
        )
    )

    args = parser.parse_args()

    pilot_path = Path(args.path)

    try:
        raw_pilots = load_pilot_files(
            pilot_path
        )

        pilots = [
            normalize_pilot(pilot)
            for pilot in raw_pilots
        ]

    except (
        FileNotFoundError,
        ValueError,
        json.JSONDecodeError
    ) as error:
        print(
            f"Pilot loading failed: {error}",
            file=sys.stderr
        )
        return 2

    if not pilots:
        print(
            f"No pilot definitions found in "
            f"{pilot_path}",
            file=sys.stderr
        )
        return 2

    print()
    print("NDT PILOT REGRESSION")
    print("=" * 80)
    print(f"Pilot path : {pilot_path}")
    print(f"Pilots     : {len(pilots)}")
    print()

    twin = DigitalTwin()

    passed = 0
    failed = 0
    observed = 0
    errors = 0

    for number, pilot in enumerate(
        pilots,
        start=1
    ):
        try:
            result = run_trace(
                twin,
                pilot
            )

            evaluation = evaluate_expectations(
                pilot,
                result
            )

            print_pilot_result(
                number=number,
                pilot=pilot,
                evaluation=evaluation,
                verbose=args.verbose
            )

            if not evaluation["has_expectations"]:
                observed += 1

                if args.fail_on_observe:
                    failed += 1

            elif evaluation["passed"]:
                passed += 1

            else:
                failed += 1

        except Exception as error:
            errors += 1

            print(
                f"{number:02d}. "
                f"{pilot['name']:<45} ERROR"
            )
            print(
                f"    {type(error).__name__}: "
                f"{error}"
            )
            print()

    print("-" * 80)
    print(f"Passed   : {passed}")
    print(f"Failed   : {failed}")
    print(f"Observed : {observed}")
    print(f"Errors   : {errors}")
    print(f"Total    : {len(pilots)}")

    if failed or errors:
        print()
        print("REGRESSION RESULT: FAILED")
        return 1

    print()
    print("REGRESSION RESULT: PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())