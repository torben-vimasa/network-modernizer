from collections import Counter
from api.digital_twin import DigitalTwin


def main():
    twin = DigitalTwin()
    graph = twin.graph

    contexts = sorted(
        graph.find_by_type("Context"),
        key=lambda x: x.name
    )

    print()
    print("NDT HEALTH CHECK")
    print("=" * 80)

    for context in contexts:
        print()
        print("=" * 80)
        print(f"CONTEXT: {context.name}")

        firewalls = []
        interfaces = []

        for relation, neighbor in graph.neighbors(context.id):
            if relation == "HAS_CONTEXT" and neighbor.type == "Firewall":
                firewalls.append(neighbor)

            if relation == "HAS_INTERFACE" and neighbor.type == "ASAInterface":
                interfaces.append(neighbor)

        print(
            "Firewall :",
            ", ".join(sorted({fw.name for fw in firewalls}))
            if firewalls
            else "NONE"
        )

        print("Interfaces:", len(interfaces))

        #
        # Global ACLs
        #
        global_acls = set()

        for firewall in firewalls:
            for relation, neighbor in graph.neighbors(firewall.id):
                if (
                    relation == "USES_GLOBAL_ACL"
                    and neighbor.type == "ACL"
                ):
                    global_acls.add(neighbor.name)

        print(
            "Global ACLs:",
            ", ".join(sorted(global_acls))
            if global_acls
            else "-"
        )

        #
        # Interface ACLs
        #
        interface_acls = set()
        interfaces_without_policy = []

        for interface in sorted(
            interfaces,
            key=lambda x: (
                x.properties.get("nameif")
                or x.properties.get("interface")
                or ""
            )
        ):
            acl_in = []
            acl_out = []

            for relationship in graph.relationships:
                if (
                    relationship.source != interface.id
                    or relationship.type != "USES_ACL"
                ):
                    continue

                acl = graph.nodes.get(
                    relationship.target
                )

                if not acl:
                    continue

                direction = relationship.properties.get(
                    "direction"
                )

                interface_acls.add(acl.name)

                if direction == "out":
                    acl_out.append(acl.name)
                else:
                    acl_in.append(acl.name)

            name = (
                interface.properties.get("nameif")
                or interface.properties.get("interface")
            )

            ip = interface.properties.get("ip")

            shutdown = interface.properties.get(
                "shutdown",
                False
            )

            if (
                not shutdown
                and not acl_in
                and not acl_out
                and not global_acls
            ):
                interfaces_without_policy.append(name)

            status = "shutdown" if shutdown else "up"

            print(
                f"  {name}"
                f" | ip={ip}"
                f" | status={status}"
                f" | in={','.join(sorted(set(acl_in))) if acl_in else '-'}"
                f" | out={','.join(sorted(set(acl_out))) if acl_out else '-'}"
            )

        #
        # ACL rule count
        #
        rule_count = sum(
            1
            for node in graph.find_by_type("ACLRule")
            if node.properties.get("context") == context.name
        )

        print("Interface ACLs:", len(interface_acls))
        print("ACL rules     :", rule_count)

        #
        # Duplicate HAS_INTERFACE relationships
        #
        ids = [
            neighbor.id
            for relation, neighbor in graph.neighbors(context.id)
            if (
                relation == "HAS_INTERFACE"
                and neighbor.type == "ASAInterface"
            )
        ]

        duplicates = {
            node_id: count
            for node_id, count in Counter(ids).items()
            if count > 1
        }

        print(
            "Duplicate interface relationships:",
            len(duplicates)
        )

        print(
            "Interfaces without policy:",
            len(interfaces_without_policy),
            f"[{', '.join(interfaces_without_policy)}]"
            if interfaces_without_policy
            else ""
        )

    print()
    print("=" * 80)
    print("HEALTH CHECK COMPLETE")


if __name__ == "__main__":
    main()