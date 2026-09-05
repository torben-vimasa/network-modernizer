import json

from dataclasses import asdict
from pathlib import Path

from parsers.cdp_neighbor_parser import CDPNeighborParser


class RouterNeighborExportBuilder:
    """
    Build normalized router neighbor observations from raw device output.

    Current discovery protocol:
        - CDP

    The exported schema is protocol-neutral through NeighborObservation,
    allowing LLDP or other discovery protocols to be added later without
    changing consumers of the normalized data.
    """

    def __init__(
        self,
        input_dirs=None,
        output_file=Path("output/router_neighbors.json")
    ):
        if input_dirs is None:
            input_dirs = [
                Path("data/router_routes"),
                Path("data/router_raw"),
            ]

        self.input_dirs = [
            Path(path)
            for path in input_dirs
        ]

        self.output_file = Path(output_file)

        self.cdp_parser = CDPNeighborParser()

    # ------------------------------------------------------------------
    # Build normalized neighbor observations
    # ------------------------------------------------------------------

    def build(self):

        all_neighbors = []

        files = self._discover_files()

        for file in files:

            try:
                lines = file.read_text(
                    encoding="utf-8",
                    errors="ignore"
                ).splitlines()

            except OSError:
                continue

            if not self._contains_cdp_output(lines):
                continue

            local_device = self._device_from_path(file)

            neighbors = self.cdp_parser.parse(
                lines,
                local_device=local_device,
                source_file=str(file)
            )

            for neighbor in neighbors:
                all_neighbors.append(
                    asdict(neighbor)
                )

        # --------------------------------------------------------------
        # Remove duplicate observations.
        #
        # The same command output may exist in more than one input file.
        # Source file is intentionally not part of the identity.
        # --------------------------------------------------------------

        unique = {}

        for neighbor in all_neighbors:

            key = (
                neighbor.get("local_device"),
                neighbor.get("local_interface"),
                neighbor.get("remote_device"),
                neighbor.get("remote_interface"),
                neighbor.get("remote_ip"),
                neighbor.get("protocol")
            )

            if key not in unique:
                unique[key] = neighbor

        all_neighbors = list(
            unique.values()
        )

        all_neighbors.sort(
            key=lambda item: (
                str(item.get("local_device") or ""),
                str(item.get("local_interface") or ""),
                str(item.get("remote_device") or ""),
                str(item.get("remote_interface") or ""),
                str(item.get("remote_ip") or "")
            )
        )

        # --------------------------------------------------------------
        # Write normalized export
        # --------------------------------------------------------------

        self.output_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with open(
            self.output_file,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                all_neighbors,
                f,
                indent=4
            )

        return all_neighbors

    # ------------------------------------------------------------------
    # Input discovery
    # ------------------------------------------------------------------

    def _discover_files(self):

        files = []

        for input_dir in self.input_dirs:

            if not input_dir.exists():
                continue

            for file in input_dir.rglob("*"):

                if not file.is_file():
                    continue

                #
                # Only ordinary textual command captures.
                # Do not attempt to parse archives/binary files.
                #
                if file.suffix.lower() not in {
                    ".txt",
                    ".log",
                    ""
                }:
                    continue

                files.append(file)

        return sorted(
            set(files)
        )

    # ------------------------------------------------------------------
    # Determine whether a file actually contains detailed CDP output
    # ------------------------------------------------------------------

    def _contains_cdp_output(self, lines):

        has_command = False
        has_device_id = False
        has_interface = False

        for line in lines:

            text = line.strip().lower()

            if (
                "show cdp" in text
                or "sh cdp" in text
            ):
                has_command = True

            if text.startswith("device id:"):
                has_device_id = True

            if text.startswith("interface:"):
                has_interface = True

            if (
                has_command
                and has_device_id
                and has_interface
            ):
                return True

        return False

    # ------------------------------------------------------------------
    # Derive local device from the input path when possible.
    #
    # Examples:
    #
    #   data/router_routes/OBvDCPe1.log
    #       -> OBvDCPe1
    #
    #   data/router_raw/OBvPe1/OBvPe1.txt
    #       -> OBvPe1
    #
    # The parser can still discover the CLI prompt when this cannot be
    # determined reliably.
    # ------------------------------------------------------------------

    def _device_from_path(self, file):

        if file.parent.name.lower() == "router_routes":
            return file.stem

        if file.parent.name.lower() == "router_raw":
            return file.stem

        if file.parent.parent.name.lower() == "router_raw":
            return file.parent.name

        return None