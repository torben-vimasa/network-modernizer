import ipaddress

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
                acls[acl_name] = ACL(
                    name=acl_name
                )

            action_index = self._find_action_index(
                parts
            )

            if action_index is None:
                continue

            action = parts[action_index]

            #
            # FTD advanced ACL using interface qualifiers:
            #
            # access-list ACL advanced permit tcp
            # ifc SOURCE_IF object SOURCE
            # ifc DEST_IF object DEST
            # object-group SERVICE
            #
            is_ftd_ifc_rule = (
                "advanced" in parts
                and len(parts) > action_index + 2
                and parts[action_index + 2] == "ifc"
            )

            source_ifc = None
            destination_ifc = None

            if is_ftd_ifc_rule:
                parsed = self._parse_ftd_ifc_rule(
                    parts,
                    action_index
                )

                if parsed is None:
                    continue

                protocol = parsed["protocol"]

                source_type = parsed["source_type"]
                source_value = parsed["source_value"]

                destination_type = parsed[
                    "destination_type"
                ]
                destination_value = parsed[
                    "destination_value"
                ]

                source_ifc = parsed["source_ifc"]
                destination_ifc = parsed[
                    "destination_ifc"
                ]

                service_info = parsed[
                    "service_info"
                ]

            else:
                #
                # Existing ASA / expanded ASA handling.
                #
                (
                    protocol,
                    service,
                    endpoint_index
                ) = self._parse_protocol_and_service(
                    parts,
                    action_index + 1
                )

                (
                    source_type,
                    source_value,
                    next_index
                ) = self._parse_endpoint(
                    parts,
                    endpoint_index
                )

                (
                    destination_type,
                    destination_value,
                    _
                ) = self._parse_endpoint(
                    parts,
                    next_index
                )

                service_info = self._extract_service(
                    parts
                )

                if service:
                    service_info["service"] = service
                    service_info[
                        "service_type"
                    ] = "object-group"

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

                service=service_info["service"],
                service_type=service_info[
                    "service_type"
                ],
                service_start=service_info[
                    "service_start"
                ],
                service_end=service_info[
                    "service_end"
                ],

                hitcnt=hitcnt,

                properties={
                    "raw": line,
                    "context": item.get("context"),
                    "source_ifc": source_ifc,
                    "destination_ifc": destination_ifc
                }
            )

            acls[acl_name].rules.append(rule)

        return list(acls.values())

    def _find_action_index(self, parts):
        for action in ["permit", "deny"]:
            if action in parts:
                return parts.index(action)

        return None

    def _parse_protocol_and_service(
        self,
        parts,
        index
    ):
        if len(parts) <= index:
            return "unknown", None, index

        token = parts[index]

        if token in [
            "tcp",
            "udp",
            "icmp",
            "ip"
        ]:
            return token, None, index + 1

        #
        # ASA service/protocol object-group:
        #
        # permit object-group SERVICE_GROUP ...
        #
        if (
            token == "object-group"
            and len(parts) > index + 1
        ):
            return (
                "object-group",
                parts[index + 1],
                index + 2
            )

        return token, None, index + 1

    def _parse_endpoint(
        self,
        parts,
        index
    ):
        if len(parts) <= index:
            return (
                "unknown",
                "unknown",
                index
            )

        token = parts[index]

        if token in ["any", "any4"]:
            return (
                "any",
                "any",
                index + 1
            )

        if (
            token == "host"
            and len(parts) > index + 1
        ):
            return (
                "host",
                parts[index + 1],
                index + 2
            )

        if (
            token == "object"
            and len(parts) > index + 1
        ):
            return (
                "object",
                parts[index + 1],
                index + 2
            )

        if (
            token == "object-group"
            and len(parts) > index + 1
        ):
            return (
                "object-group",
                parts[index + 1],
                index + 2
            )

        #
        # Expanded ASA network syntax:
        #
        # 157.250.163.240 255.255.255.248
        #
        if len(parts) > index + 1:
            mask = parts[index + 1]

            try:
                network = ipaddress.ip_network(
                    f"{token}/{mask}",
                    strict=False
                )

            except ValueError:
                pass

            else:
                return (
                    "network",
                    str(network),
                    index + 2
                )

        return (
            "raw",
            token,
            index + 1
        )

    def _parse_ftd_ifc_rule(
        self,
        parts,
        action_index
    ):
        #
        # Expected structure:
        #
        # advanced permit tcp
        # ifc SOURCE_IF
        # object/object-group SOURCE
        # ifc DEST_IF
        # object/object-group DEST
        # [object-group SERVICE]
        # [rule-id ...]
        #

        protocol_index = action_index + 1

        if len(parts) <= protocol_index:
            return None

        protocol = parts[protocol_index]

        cursor = protocol_index + 1

        #
        # Source interface
        #
        if (
            len(parts) <= cursor
            or parts[cursor] != "ifc"
        ):
            return None

        if len(parts) <= cursor + 1:
            return None

        source_ifc = parts[cursor + 1]
        cursor += 2

        #
        # Source endpoint
        #
        (
            source_type,
            source_value,
            cursor
        ) = self._parse_endpoint(
            parts,
            cursor
        )

        #
        # Destination interface
        #
        if (
            len(parts) <= cursor
            or parts[cursor] != "ifc"
        ):
            return None

        if len(parts) <= cursor + 1:
            return None

        destination_ifc = parts[
            cursor + 1
        ]

        cursor += 2

        #
        # Destination endpoint
        #
        (
            destination_type,
            destination_value,
            cursor
        ) = self._parse_endpoint(
            parts,
            cursor
        )

        #
        # Destination service begins after
        # destination endpoint.
        #
        service_info = (
            self._extract_service_from_index(
                parts,
                cursor
            )
        )

        return {
            "protocol": protocol,

            "source_ifc": source_ifc,
            "source_type": source_type,
            "source_value": source_value,

            "destination_ifc": destination_ifc,
            "destination_type": destination_type,
            "destination_value": destination_value,

            "service_info": service_info
        }

    def _extract_service_from_index(
        self,
        parts,
        index
    ):
        result = {
            "service": None,
            "service_type": None,
            "service_start": None,
            "service_end": None
        }

        if len(parts) <= index:
            return result

        token = parts[index]

        #
        # FTD:
        #
        # object-group HTTPS
        #
        if (
            token == "object-group"
            and len(parts) > index + 1
        ):
            value = parts[index + 1]

            result["service"] = value
            result[
                "service_type"
            ] = "object-group"

            return result

        #
        # eq 1514
        #
        if (
            token == "eq"
            and len(parts) > index + 1
        ):
            value = parts[index + 1]

            result["service"] = value
            result["service_type"] = "eq"
            result["service_start"] = value
            result["service_end"] = value

            return result

        #
        # range 49152 65535
        #
        if (
            token == "range"
            and len(parts) > index + 2
        ):
            start = parts[index + 1]
            end = parts[index + 2]

            result["service_type"] = "range"
            result["service_start"] = start
            result["service_end"] = end

            return result

        return result

    def _find_hitcnt(self, line):
        marker = "hitcnt="

        if marker not in line:
            return None

        after = line.split(
            marker,
            1
        )[1]

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
        result = {
            "service": None,
            "service_type": None,
            "service_start": None,
            "service_end": None
        }

        if "eq" in parts:
            index = parts.index("eq")

            if len(parts) > index + 1:
                value = parts[index + 1]

                result["service"] = value
                result["service_type"] = "eq"
                result["service_start"] = value
                result["service_end"] = value

                return result

        if "range" in parts:
            index = parts.index("range")

            if len(parts) > index + 2:
                start = parts[index + 1]
                end = parts[index + 2]

                result["service_type"] = "range"
                result["service_start"] = start
                result["service_end"] = end

                return result

        return result