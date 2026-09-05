import re

from models.neighbor_observation import NeighborObservation


class CDPNeighborParser:
    """
    Parse Cisco 'show cdp neighbors detail' output into normalized
    NeighborObservation objects.

    Designed to tolerate output variations from IOS, IOS-XE,
    NX-OS and IOS-XR.
    """

    def parse(
        self,
        lines,
        local_device=None,
        source_file=None
    ):
        observations = []

        current = None
        version_lines = []
        collecting_version = False

        for raw_line in lines:

            line = raw_line.rstrip("\r\n")
            stripped = line.strip()

            # ----------------------------------------------------------
            # Try to discover local device from CLI prompt
            # ----------------------------------------------------------

            prompt_device = self._extract_prompt_device(stripped)

            if prompt_device and not local_device:
                local_device = prompt_device

            # ----------------------------------------------------------
            # New CDP neighbor block
            # ----------------------------------------------------------

            device_match = re.match(
                r"^Device\s+ID\s*:\s*(.+?)\s*$",
                stripped,
                re.IGNORECASE
            )

            if device_match:

                if current:
                    observation = self._build_observation(
                        current=current,
                        version_lines=version_lines,
                        local_device=local_device,
                        source_file=source_file
                    )

                    if observation:
                        observations.append(observation)

                current = {
                    "remote_device": device_match.group(1).strip(),
                    "system_name": None,
                    "remote_ip": None,
                    "platform": None,
                    "local_interface": None,
                    "remote_interface": None,
                }

                version_lines = []
                collecting_version = False
                continue

            if current is None:
                continue

            # ----------------------------------------------------------
            # System name
            #
            # Seen as:
            #   System Name: OBvP1.baneisp.dk
            #   SysName : OBvP1.baneisp.dk
            # ----------------------------------------------------------

            system_match = re.match(
                r"^(?:System\s+Name|SysName)\s*:\s*(.*?)\s*$",
                stripped,
                re.IGNORECASE
            )

            if system_match:
                value = system_match.group(1).strip()

                if value:
                    current["system_name"] = value

                continue

            # ----------------------------------------------------------
            # IPv4 address
            #
            # Seen as:
            #   IPv4 Address: 172.17.90.213
            #   IPv4 address: 172.21.240.1
            # ----------------------------------------------------------

            ip_match = re.match(
                r"^IPv4\s+address\s*:\s*"
                r"(\d{1,3}(?:\.\d{1,3}){3})\s*$",
                stripped,
                re.IGNORECASE
            )

            if ip_match:
                current["remote_ip"] = ip_match.group(1)
                continue

            # ----------------------------------------------------------
            # Platform
            # ----------------------------------------------------------

            platform_match = re.match(
                r"^Platform\s*:\s*(.+?)(?:,\s*Capabilities\s*:.*)?$",
                stripped,
                re.IGNORECASE
            )

            if platform_match:
                current["platform"] = platform_match.group(1).strip()
                continue

            # ----------------------------------------------------------
            # Local interface + optional remote Port ID on same line
            #
            # Supported forms:
            #
            #   Interface: Ethernet1/3,
            #     Port ID (outgoing port): TenGigE0/0/1/1
            #
            #   Interface: Ethernet1/3, Port ID (outgoing port):
            #     TenGigE0/0/1/1
            #
            #   Interface: TenGigE0/0/0/8
            #   Port ID (outgoing port): TenGigE0/0/1/3
            # ----------------------------------------------------------

            interface_match = re.match(
                r"^Interface\s*:\s*(.+?)"
                r"(?:,\s*Port\s+ID\s*"
                r"(?:\(outgoing\s+port\))?\s*:\s*(.+?))?\s*$",
                stripped,
                re.IGNORECASE
            )

            if interface_match:
                current["local_interface"] = (
                    interface_match.group(1).strip().rstrip(",")
                )

                if interface_match.group(2):
                    current["remote_interface"] = (
                        interface_match.group(2).strip()
                    )

                continue

            # ----------------------------------------------------------
            # Remote interface / Port ID on separate line
            # ----------------------------------------------------------

            port_match = re.match(
                r"^Port\s+ID\s*"
                r"(?:\(outgoing\s+port\))?\s*:\s*(.+?)\s*$",
                stripped,
                re.IGNORECASE
            )

            if port_match:
                current["remote_interface"] = (
                    port_match.group(1).strip()
                )
                continue

            # ----------------------------------------------------------
            # Version section
            # ----------------------------------------------------------

            if re.match(
                r"^Version\s*:\s*$",
                stripped,
                re.IGNORECASE
            ):
                collecting_version = True
                version_lines = []
                continue

            if collecting_version:

                # Known fields after the Version section.
                if re.match(
                    r"^(?:advertisement\s+version|"
                    r"Advertisement\s+Version|"
                    r"Native\s+VLAN|"
                    r"Duplex|"
                    r"Management\s+address)",
                    stripped,
                    re.IGNORECASE
                ):
                    collecting_version = False
                    continue

                if stripped:
                    version_lines.append(stripped)

        # --------------------------------------------------------------
        # Last block
        # --------------------------------------------------------------

        if current:
            observation = self._build_observation(
                current=current,
                version_lines=version_lines,
                local_device=local_device,
                source_file=source_file
            )

            if observation:
                observations.append(observation)

        return observations

    # ------------------------------------------------------------------
    # Build normalized observation
    # ------------------------------------------------------------------

    def _build_observation(
        self,
        current,
        version_lines,
        local_device,
        source_file
    ):

        remote_device = (
            current.get("system_name")
            or current.get("remote_device")
        )

        local_interface = current.get("local_interface")
        remote_interface = current.get("remote_interface")

        # A topology observation without these fields cannot describe
        # a usable adjacency.
        if not remote_device:
            return None

        if not local_interface:
            return None

        if not remote_interface:
            return None

        software = None

        if version_lines:
            software = " ".join(version_lines).strip()

        return NeighborObservation(
            local_device=local_device or "unknown",
            local_interface=local_interface,
            remote_device=remote_device,
            remote_interface=remote_interface,
            remote_ip=current.get("remote_ip"),
            protocol="cdp",
            system_name=current.get("system_name"),
            platform=current.get("platform"),
            software=software,
            source_file=source_file,
            confidence="high"
        )

    # ------------------------------------------------------------------
    # CLI prompt helper
    # ------------------------------------------------------------------

    def _extract_prompt_device(self, line):

        if not line or "#" not in line:
            return None

        prompt = line.split("#", 1)[0].strip()

        if not prompt:
            return None

        # IOS-XR:
        # RP/0/RSP0/CPU0:OBvDCR1#
        if ":" in prompt:
            prompt = prompt.rsplit(":", 1)[-1].strip()

        # Reject obvious text that merely happens to contain '#'.
        if not re.match(
            r"^[A-Za-z0-9_.-]+$",
            prompt
        ):
            return None

        return prompt