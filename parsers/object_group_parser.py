from models.network_object import NetworkObject
from models.object_group import ObjectGroup


class ObjectParser:
    def parse_context_file(self, context_name, lines):
        network_objects = []
        object_groups = []

        current_object = None
        current_group = None

        for raw_line in lines:
            line = raw_line.strip()

            if not line or line == "!":
                current_object = None
                current_group = None
                continue

            if line.startswith("object network "):
                name = line.replace("object network ", "").strip()

                current_object = NetworkObject(
                    name=f"{context_name}:{name}",
                    object_type="unknown",
                    value=""
                )

                network_objects.append(current_object)
                current_group = None
                continue

            if line.startswith("object-group network "):
                name = line.replace("object-group network ", "").strip()

                current_group = ObjectGroup(
                    name=f"{context_name}:{name}"
                )

                object_groups.append(current_group)
                current_object = None
                continue

            if line.startswith("object-group service "):
                name = line.replace("object-group service ", "").strip()

                current_group = ObjectGroup(
                    name=f"{context_name}:{name}"
                )

                object_groups.append(current_group)
                current_object = None
                continue

            if current_object:
                if line.startswith("host "):
                    current_object.object_type = "host"
                    current_object.value = line.replace("host ", "").strip()

                elif line.startswith("subnet "):
                    current_object.object_type = "subnet"
                    current_object.value = line.replace("subnet ", "").strip()

                elif line.startswith("range "):
                    current_object.object_type = "range"
                    current_object.value = line.replace("range ", "").strip()

                elif line.startswith("fqdn "):
                    current_object.object_type = "fqdn"
                    current_object.value = line.replace("fqdn ", "").strip()

            if current_group:
                if line.startswith("network-object object "):
                    member = line.replace("network-object object ", "").strip()
                    current_group.members.append(f"{context_name}:{member}")

                elif line.startswith("network-object "):
                    member = line.replace("network-object ", "").strip()
                    current_group.members.append(member)

                elif line.startswith("group-object "):
                    member = line.replace("group-object ", "").strip()
                    current_group.members.append(f"{context_name}:{member}")

                elif line.startswith("service-object "):
                    member = line.replace("service-object ", "").strip()
                    current_group.members.append(member)

        return network_objects, object_groups