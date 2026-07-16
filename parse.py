import json
from pathlib import Path

CONTEXTS_DIR = Path("data/contexts")
OUTPUT_DIR = Path("output")


def parse_context_file(context_file: Path) -> dict:
    context_name = context_file.stem

    with open(context_file, "r", encoding="utf-8", errors="ignore") as handle:
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

        if line.startswith("interface "):
            if current_interface is not None:
                interfaces.append(current_interface)

            current_interface = {
                "context": context_name,
                "physical_interface": line.replace("interface ", "", 1),
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
                current_interface["asa_interface"] = line.replace("nameif ", "", 1)
                continue

            if line.startswith("security-level "):
                current_interface["security_level"] = line.replace("security-level ", "", 1)
                continue

            if line.startswith("ip address "):
                parts = line.split()

                if len(parts) >= 4:
                    current_interface["ip_address"] = parts[2]
                    current_interface["subnet_mask"] = parts[3]

                if "standby" in parts:
                    standby_index = parts.index("standby")
                    if len(parts) > standby_index + 1:
                        current_interface["standby_ip"] = parts[standby_index + 1]

                interfaces.append(current_interface)
                current_interface = None
                continue

            if line == "!":
                interfaces.append(current_interface)
                current_interface = None
                continue

        if line.startswith("name "):
            name_count += 1

        if line.startswith("object network "):
            object_count += 1

        if line.startswith("access-group "):
            parts = line.split()

            if len(parts) >= 5:
                access_groups.append({
                    "context": context_name,
                    "acl": parts[1],
                    "direction": parts[2],
                    "asa_interface": parts[4],
                    "raw": line
                })

            continue

        if line.startswith("access-list "):
            if " remark " in f" {line} ":
                continue

            if " permit " not in f" {line} " and " deny " not in f" {line} ":
                continue

            parts = line.split()

            if len(parts) < 3:
                continue

            acl_name = parts[1]
            acl_counts[acl_name] = acl_counts.get(acl_name, 0) + 1

            rules.append({
                "context": context_name,
                "acl": acl_name,
                "rule": line,
                "asa_interface": None
            })

            if " any any" in line or " any4 any4" in line:
                any_any_rules.append(line)

    if current_interface is not None:
        interfaces.append(current_interface)

    acl_to_interface = {
        access_group["acl"]: access_group["asa_interface"]
        for access_group in access_groups
    }

    for rule in rules:
        rule["asa_interface"] = acl_to_interface.get(rule["acl"], "unknown")

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


def main() -> None:
    OUTPUT_DIR.mkdir(exist_ok=True)

    if not CONTEXTS_DIR.exists():
        raise FileNotFoundError(f"Context directory does not exist: {CONTEXTS_DIR}")

    context_files = sorted(CONTEXTS_DIR.glob("*.txt"))

    if not context_files:
        raise FileNotFoundError(f"No context files found in {CONTEXTS_DIR}")

    all_rules = []
    all_interfaces = []
    all_access_groups = []
    context_reports = []
    global_acl_counts = {}
    total_names = 0
    total_objects = 0
    total_any_any = 0

    print(f"Contexts found: {len(context_files)}")

    for context_file in context_files:
        result = parse_context_file(context_file)

        all_rules.extend(result["rules"])
        all_interfaces.extend(result["interfaces"])
        all_access_groups.extend(result["access_groups"])

        total_names += result["names"]
        total_objects += result["objects"]
        total_any_any += len(result["any_any_rules"])

        for acl_name, count in result["acl_counts"].items():
            global_acl_counts[f"{result['context']}:{acl_name}"] = count

        context_reports.append({
            "context": result["context"],
            "names": result["names"],
            "objects": result["objects"],
            "access_lists": len(result["rules"]),
            "acl_count": len(result["acl_counts"]),
            "interfaces": len(result["interfaces"]),
            "access_groups": len(result["access_groups"]),
            "any_any_rules": len(result["any_any_rules"])
        })

        print(
            f"{result['context']}: "
            f"{len(result['rules'])} rules, "
            f"{len(result['acl_counts'])} ACLs, "
            f"{len(result['interfaces'])} interfaces, "
            f"{len(result['access_groups'])} access-groups"
        )

    report = {
        "contexts": len(context_files),
        "names": total_names,
        "objects": total_objects,
        "access_lists": len(all_rules),
        "any_any_rules": total_any_any,
        "acl_count": len(global_acl_counts),
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
        ("access_groups.json", all_access_groups)
    ]:
        with open(OUTPUT_DIR / filename, "w", encoding="utf-8") as handle:
            json.dump(content, handle, indent=4, ensure_ascii=False)

    print()
    print("Output written:")
    print("output/report.json")
    print("output/rules.json")
    print("output/interfaces.json")
    print("output/access_groups.json")
    print()
    print(f"Rules: {len(all_rules)}")
    print(f"Interfaces: {len(all_interfaces)}")
    print(f"Access-groups: {len(all_access_groups)}")


if __name__ == "__main__":
    main()
