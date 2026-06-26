from models.acl import ACL
from models.acl_rule import ACLRule


class ACLRuleParser:
    def parse_rules(self, raw_rules):
        acls = {}

        for index, item in enumerate(raw_rules, start=1):
            line = item["rule"]

            if not line.startswith("access-list "):
                continue

            parts = line.split()

            if len(parts) < 5:
                continue

            acl_name = parts[1]

            if acl_name not in acls:
                acls[acl_name] = ACL(name=acl_name)

            action_index = self._find_action_index(parts)

            if action_index is None:
                continue

            action = parts[action_index]

            protocol, service, endpoint_index = self._parse_protocol_and_service(
                parts,
                action_index + 1
            )

            source_type, source_value, next_index = self._parse_endpoint(
                parts,
                endpoint_index
            )

            destination_type, destination_value, _ = self._parse_endpoint(
                parts,
                next_index
            )

            hitcnt = self._find_hitcnt(line)

            rule = ACLRule(
                acl_name=acl_name,
                sequence=index,
                action=action,
                protocol=protocol,

                source=source_value,
                destination=destination_value,

                source_type=source_type,
                source_value=source_value,

                destination_type=destination_type,
                destination_value=destination_value,

                service=service or self._extract_service(parts),
                hitcnt=hitcnt,
                properties={
                    "raw": line
                }
            )

            acls[acl_name].rules.append(rule)

        return list(acls.values())

    def _find_action_index(self, parts):
        for action in ["permit", "deny"]:
            if action in parts:
                return parts.index(action)

        return None

    def _parse_protocol_and_service(self, parts, index):
        if len(parts) <= index:
            return "unknown", None, index

        token = parts[index]

        if token in ["tcp", "udp", "icmp", "ip"]:
            return token, None, index + 1

        # ASA can use object-group as service/protocol position:
        # permit object-group SERVICE_GROUP host x object y
        if token == "object-group" and len(parts) > index + 1:
            return "object-group", parts[index + 1], index + 2

        return token, None, index + 1

    def _parse_endpoint(self, parts, index):
        if len(parts) <= index:
            return "unknown", "unknown", index

        token = parts[index]

        if token == "any":
            return "any", "any", index + 1

        if token == "host" and len(parts) > index + 1:
            return "host", parts[index + 1], index + 2

        if token == "object" and len(parts) > index + 1:
            return "object", parts[index + 1], index + 2

        if token == "object-group" and len(parts) > index + 1:
            return "object-group", parts[index + 1], index + 2

        return "raw", token, index + 1

    def _find_hitcnt(self, line):
        marker = "hitcnt="

        if marker not in line:
            return None

        after = line.split(marker, 1)[1]
        value = ""

        for char in after:
            if char.isdigit():
                value += char
            else:
                break

        if not value:
            return None

        return int(value)

    def _extract_service(self, parts):
        if "eq" in parts:
            index = parts.index("eq")

            if len(parts) > index + 1:
                return parts[index + 1]

        return None