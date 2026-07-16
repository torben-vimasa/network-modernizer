import ipaddress
import re

from models.acl import ACL
from models.acl_rule import ACLRule


class ACLRuleParser:

    def parse_rules(self, raw_rules):
        acls = {}

        for index, item in enumerate(raw_rules, start=1):
            line = item["rule"].strip()

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
            line_number = self._find_line_number(parts)

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
                    "raw": line,
                    "line_number": line_number,
                    "context": item.get("context"),
                    "asa_interface": item.get("asa_interface")
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

        if token in ["tcp", "udp", "icmp", "icmp6", "ip"]:
            return token, None, index + 1

        if token in ["object-group", "object"] and len(parts) > index + 1:
            return token, parts[index + 1], index + 2

        return token, None, index + 1

    def _parse_endpoint(self, parts, index):
        if len(parts) <= index:
            return "unknown", "unknown", index

        token = parts[index]

        if token in ["any", "any4", "any6"]:
            return "any", token, index + 1

        if token == "host" and len(parts) > index + 1:
            return "host", parts[index + 1], index + 2

        if token == "object" and len(parts) > index + 1:
            return "object", parts[index + 1], index + 2

        if token == "object-group" and len(parts) > index + 1:
            return "object-group", parts[index + 1], index + 2

        if (
            self._is_ipv4(token)
            and len(parts) > index + 1
            and self._is_ipv4_netmask(parts[index + 1])
        ):
            network = ipaddress.ip_network(
                f"{token}/{parts[index + 1]}",
                strict=False
            )
            return "network", str(network), index + 2

        if self._is_ipv4(token):
            return "host", token, index + 1

        return "raw", token, index + 1

    def _is_ipv4(self, value):
        try:
            return ipaddress.ip_address(value).version == 4
        except ValueError:
            return False

    def _is_ipv4_netmask(self, value):
        try:
            ipaddress.ip_network(f"0.0.0.0/{value}")
            return True
        except ValueError:
            return False

    def _find_line_number(self, parts):
        if "line" not in parts:
            return None

        index = parts.index("line")

        if len(parts) <= index + 1:
            return None

        try:
            return int(parts[index + 1])
        except ValueError:
            return None

    def _find_hitcnt(self, line):
        match = re.search(r"\(hitcnt=(\d+)\)", line)
        return int(match.group(1)) if match else None

    def _extract_service(self, parts):
        if "eq" in parts:
            index = parts.index("eq")
            if len(parts) > index + 1:
                return parts[index + 1]

        if "range" in parts:
            index = parts.index("range")
            if len(parts) > index + 2:
                return f"{parts[index + 1]}-{parts[index + 2]}"

        return None
