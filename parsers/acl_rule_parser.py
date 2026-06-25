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

            if len(parts) < 6:
                continue

            acl_name = parts[1]

            if acl_name not in acls:
                acls[acl_name] = ACL(name=acl_name)

            action = self._find_action(parts)
            protocol = self._find_protocol(parts)
            hitcnt = self._find_hitcnt(line)

            rule = ACLRule(
                acl_name=acl_name,
                sequence=index,
                action=action,
                protocol=protocol,
                source=self._safe_token(parts, 5),
                destination=self._safe_token(parts, 6),
                service=self._extract_service(parts),
                hitcnt=hitcnt,
                properties={
                    "raw": line
                }
            )

            acls[acl_name].rules.append(rule)

        return list(acls.values())

    def _find_action(self, parts):
        for action in ["permit", "deny"]:
            if action in parts:
                return action

        return "unknown"

    def _find_protocol(self, parts):
        for protocol in ["tcp", "udp", "icmp", "ip"]:
            if protocol in parts:
                return protocol

        return "unknown"

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

    def _safe_token(self, parts, index):
        if len(parts) > index:
            return parts[index]

        return "unknown"