import json
from pathlib import Path
from parsers.object_group_parser import ObjectParser
from utils.firewall_context import detect_firewall_context


CONTEXTS_DIR = Path("data/contexts")
FIREWALLS_DIR = Path("data/firewalls")
OUTPUT_DIR = Path("output")


def parse_context_file(context_file: Path) -> dict:
    context_name = detect_firewall_context(context_file)

    with open(
        context_file,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as handle:
        lines = handle.readlines()

    name_count = 0
    object_count = 0
    any_any_rules = []
    acl_counts = {}

    rules = []
    interfaces = []
    access_groups = []

    current_interface = None

    for raw_line in lines:
        line = raw_line.strip()

        if not line:
            continue

        #
        # Interfaces
        #
        if line.startswith("interface "):
            if current_interface is not None:
                interfaces.append(current_interface)

            current_interface = {
                "context": context_name,
                "physical_interface": line.replace(
                    "interface ",
                    "",
                    1
                ),
                "asa_interface": None,
                "security_level": None,
                "ip_address": None,
                "subnet_mask": None,
                "standby_ip": None,
                "shutdown": False
            }

            continue

        if current_interface is not None:

            if line == "shutdown":
                current_interface["shutdown"] = True
                continue

            if line.startswith("nameif "):
                current_interface["asa_interface"] = line.replace(
                    "nameif ",
                    "",
                    1
                )
                continue

            if line.startswith("security-level "):
                current_interface["security_level"] = line.replace(
                    "security-level ",
                    "",
                    1
                )
                continue

            if line.startswith("ip address "):
                parts = line.split()

                if len(parts) >= 4:
                    current_interface["ip_address"] = parts[2]
                    current_interface["subnet_mask"] = parts[3]

                if "standby" in parts:
                    standby_index = parts.index("standby")

                    if len(parts) > standby_index + 1:
                        current_interface["standby_ip"] = (
                            parts[standby_index + 1]
                        )

                interfaces.append(current_interface)
                current_interface = None

                continue

            if line == "!":
                interfaces.append(current_interface)
                current_interface = None

                continue

        #
        # Basic inventory counters
        #
        if line.startswith("name "):
            name_count += 1

        if line.startswith("object network "):
            object_count += 1

        #
        # Access-group bindings
        #
        if line.startswith("access-group "):
            parts = line.split()

            #
            # FTD global ACL:
            #
            # access-group CSM_FW_ACL_ global
            #
            if (
                len(parts) == 3
                and parts[2].lower() == "global"
            ):
                access_groups.append({
                    "context": context_name,
                    "acl": parts[1],
                    "direction": "global",
                    "asa_interface": None,
                    "raw": line
                })

                continue

            #
            # Classic ASA:
            #
            # access-group ACL_NAME in interface NAMEIF
            # access-group ACL_NAME out interface NAMEIF
            #
            if len(parts) >= 5:
                access_groups.append({
                    "context": context_name,
                    "acl": parts[1],
                    "direction": parts[2],
                    "asa_interface": parts[4],
                    "raw": line
                })

            continue

        #
        # ACL rules
        #
        if line.startswith("access-list "):

            if " remark " in f" {line} ":
                continue

            if (
                " permit " not in f" {line} "
                and " deny " not in f" {line} "
            ):
                continue

            parts = line.split()

            if len(parts) < 3:
                continue

            acl_name = parts[1]

            acl_counts[acl_name] = (
                acl_counts.get(acl_name, 0) + 1
            )

            rules.append({
                "context": context_name,
                "acl": acl_name,
                "rule": line,
                "asa_interface": None
            })

            if (
                " any any" in line
                or " any4 any4" in line
            ):
                any_any_rules.append(line)

    #
    # Flush unfinished interface
    #
    if current_interface is not None:
        interfaces.append(current_interface)

    
    return {
        "context": context_name,
        "names": name_count,
        "objects": object_count,
        "acl_counts": acl_counts,
        "rules": rules,
        "interfaces": interfaces,
        "access_groups": access_groups,
        "any_any_rules": any_any_rules
    }
def deduplicate_network_objects(
        objects
    ):

        by_name = {}

        for obj in objects:

            name = obj.name

            existing = by_name.get(
                name
            )

            if existing is None:

                by_name[
                    name
                ] = obj

                continue

            existing_value = str(
                existing.value or ""
            ).strip()

            candidate_value = str(
                obj.value or ""
            ).strip()

            existing_type = str(
                existing.object_type or "unknown"
            ).lower()

            candidate_type = str(
                obj.object_type or "unknown"
            ).lower()

            existing_concrete = (
                existing_type != "unknown"
                and bool(existing_value)
            )

            candidate_concrete = (
                candidate_type != "unknown"
                and bool(candidate_value)
            )

            #
            # Concrete definition always wins over
            # an unresolved/empty placeholder.
            #
            if (
                candidate_concrete
                and not existing_concrete
            ):

                by_name[
                    name
                ] = obj

                continue

            #
            # Existing concrete definition wins over
            # a later unresolved/empty placeholder.
            #
            if (
                existing_concrete
                and not candidate_concrete
            ):

                continue

            #
            # If both definitions are concrete and identical,
            # simply keep the first one.
            #
            if (
                existing_concrete
                and candidate_concrete
                and existing_type == candidate_type
                and existing_value == candidate_value
            ):

                continue

            #
            # Conflicting concrete definitions must not
            # silently overwrite each other.
            #
            if (
                existing_concrete
                and candidate_concrete
            ):

                print(
                    "WARNING: conflicting NetworkObject "
                    f"definition for {name}: "
                    f"{existing_type}={existing_value} "
                    f"vs "
                    f"{candidate_type}={candidate_value}"
                )

                continue

            #
            # Both are unresolved placeholders.
            # Keep the first one.
            #

        return list(
            by_name.values()
        )

def main() -> None:
    OUTPUT_DIR.mkdir(exist_ok=True)

    if not CONTEXTS_DIR.exists():
        raise FileNotFoundError(
            f"Context directory does not exist: {CONTEXTS_DIR}"
        )

    if not FIREWALLS_DIR.exists():
        raise FileNotFoundError(
            f"Firewall directory does not exist: {FIREWALLS_DIR}"
        )

    #
    # Existing ASA contexts
    #
    context_files = sorted(
        CONTEXTS_DIR.glob("*.txt")
    )

    #
    # Additional standalone firewall configs,
    # including CAT2/CAT3/FTD.
    #
    firewall_files = sorted(
        FIREWALLS_DIR.glob("*.txt")
    )

    #
    # Avoid parsing the same device twice.
    #
    # data/contexts is authoritative when the same
    # stem also exists under data/firewalls.
    #
    context_stems = {
        path.stem
        for path in context_files
    }

    firewall_files = [
        path
        for path in firewall_files
        if path.stem not in context_stems
    ]

    input_files = (
        context_files
        + firewall_files
    )

    if not input_files:
        raise FileNotFoundError(
            "No context or firewall files found"
        )

    all_rules = []
    all_interfaces = []
    all_access_groups = []

    object_parser = ObjectParser()

    all_network_objects = []
    all_object_groups = []

    context_reports = []
    global_acl_counts = {}

    total_names = 0
    total_objects = 0
    total_any_any = 0

    print(
        f"Contexts found : {len(context_files)}"
    )

    print(
        f"Firewalls found: {len(firewall_files)}"
    )

    print(
        f"Input files    : {len(input_files)}"
    )

    print()

    for input_file in input_files:
        result = parse_context_file(
            input_file
        )
        with open(
            input_file,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as handle:
            lines = handle.readlines()

        network_objects, object_groups = (
            object_parser.parse_context_file(
                input_file.stem,
                lines
            )
        )

        all_network_objects.extend(
            network_objects
        )

        all_object_groups.extend(
            object_groups
)
        all_rules.extend(
            result["rules"]
        )

        all_interfaces.extend(
            result["interfaces"]
        )

        all_access_groups.extend(
            result["access_groups"]
        )

        total_names += result["names"]
        total_objects += result["objects"]
        total_any_any += len(
            result["any_any_rules"]
        )

        for acl_name, count in result["acl_counts"].items():
            global_acl_counts[
                f"{result['context']}:{acl_name}"
            ] = count

        context_reports.append({
            "context": result["context"],
            "names": result["names"],
            "objects": result["objects"],
            "access_lists": len(
                result["rules"]
            ),
            "acl_count": len(
                result["acl_counts"]
            ),
            "interfaces": len(
                result["interfaces"]
            ),
            "access_groups": len(
                result["access_groups"]
            ),
            "any_any_rules": len(
                result["any_any_rules"]
            )
        })

        print(
            f"{result['context']}: "
            f"{len(result['rules'])} rules, "
            f"{len(result['acl_counts'])} ACLs, "
            f"{len(result['interfaces'])} interfaces, "
            f"{len(result['access_groups'])} access-groups"
        )

    original_network_object_count = len(
        all_network_objects
    )

    all_network_objects = (
        deduplicate_network_objects(
            all_network_objects
        )
    )

    deduplicated_network_object_count = len(
        all_network_objects
    )

    removed_network_object_duplicates = (
        original_network_object_count
        - deduplicated_network_object_count
    )

    print()
    print(
        "Network objects before deduplication: "
        f"{original_network_object_count}"
    )
    print(
        "Network objects after deduplication : "
        f"{deduplicated_network_object_count}"
    )
    print(
        "Duplicate object definitions removed: "
        f"{removed_network_object_duplicates}"
    )

    network_objects_json = [
        {
            "name": obj.name,
            "type": obj.object_type,
            "value": obj.value
        }
        for obj in all_network_objects
    ]

    object_groups_json = [
        {
            "name": group.name,
            "members": group.members
        }
        for group in all_object_groups
    ]

    report = {
        "contexts": len(context_files),
        "firewalls": len(firewall_files),
        "input_files": len(input_files),

        "names": total_names,
        "objects": total_objects,

        "access_lists": len(all_rules),
        "any_any_rules": total_any_any,

        "acl_count": len(
            global_acl_counts
        ),

        "top_acls": dict(
            sorted(
                global_acl_counts.items(),
                key=lambda item: item[1],
                reverse=True
            )[:20]
        ),

        "context_reports": context_reports
    }

    for filename, content in [
        ("report.json", report),
        ("rules.json", all_rules),
        ("interfaces.json", all_interfaces),
        ("access_groups.json", all_access_groups),
        ("network_objects.json", network_objects_json),
        ("object_groups.json", object_groups_json)
    ]:
        with open(
            OUTPUT_DIR / filename,
            "w",
            encoding="utf-8"
        ) as handle:
            json.dump(
                content,
                handle,
                indent=4,
                ensure_ascii=False
            )

    print()
    print("Output written:")
    print("output/report.json")
    print("output/rules.json")
    print("output/interfaces.json")
    print("output/access_groups.json")
    print()

    print(
        f"Rules: {len(all_rules)}"
    )

    print(
        f"Interfaces: {len(all_interfaces)}"
    )

    print(
        f"Access-groups: {len(all_access_groups)}"
    )

    print(
    f"Network objects: {len(all_network_objects)}"
    )

    print(
        f"Object groups: {len(all_object_groups)}"
)


if __name__ == "__main__":
    main()