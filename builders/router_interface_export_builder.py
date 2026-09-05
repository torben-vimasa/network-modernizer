import json

from dataclasses import asdict
from pathlib import Path

from parsers.router_interface_parser import RouterInterfaceParser
from parsers.router_inventory_parser import RouterInventoryParser


class RouterInterfaceExportBuilder:

    def __init__(
        self,
        input_dir=Path("data/router_raw_clean"),
        router_raw_dir=Path("data/router_raw"),
        output_file=Path("output/router_interfaces.json")
    ):
        self.input_dir = Path(input_dir)
        self.router_raw_dir = Path(router_raw_dir)
        self.output_file = Path(output_file)

        self.parser = RouterInterfaceParser()
        self.inventory_parser = RouterInventoryParser()


    def build(self):

        all_interfaces = []

        #
        # Existing normalized interface data.
        #
        # Preserve the existing schema exactly.
        #
        if self.input_dir.exists():

            for file in sorted(
                self.input_dir.glob("*.txt")
            ):

                device = file.stem.split("-")[0]

                with open(
                    file,
                    encoding="utf-8",
                    errors="ignore"
                ) as f:

                    interfaces = self.parser.parse(
                        f.readlines(),
                        device=device
                    )

                for interface in interfaces:

                    all_interfaces.append(
                        asdict(interface)
                    )

        #
        # Raw router inventory.
        #
        if self.router_raw_dir.exists():

            raw_files = []

            #
            # Existing supported command-output files.
            #
            raw_files.extend(
                self.router_raw_dir.rglob(
                    "*section interface*.txt"
                )
            )

            raw_files.extend(
                self.router_raw_dir.rglob(
                    "*show running-config.txt"
                )
            )

            #
            # Full router configurations.
            #
            # Generic convention:
            #
            #   data/router_raw/OBvPe1/OBvPe1.txt
            #   data/router_raw/OBvPe2/OBvPe2.txt
            #
            # The filename must match the parent directory name.
            #
            for file in self.router_raw_dir.rglob("*.txt"):

                if (
                    file.stem.lower()
                    == file.parent.name.lower()
                ):

                    raw_files.append(
                        file
                    )

            raw_files = sorted(
                set(raw_files)
            )

            for file in raw_files:

                lines = file.read_text(
                    encoding="utf-8",
                    errors="ignore"
                ).splitlines()

                router = self.inventory_parser.parse(
                    file.parent.name,
                    lines
                )

                for interface in router.interfaces:

                    #
                    # Convert RouterInventoryParser output
                    # to the existing router_interfaces.json
                    # schema.
                    #
                    mask = None

                    if interface.prefix:

                        try:
                            mask = interface.prefix.split(
                                "/",
                                1
                            )[1]

                        except IndexError:
                            mask = None

                    all_interfaces.append(
                        {
                            "device": router.name,
                            "interface": interface.name,
                            "vrf": interface.vrf,
                            "ip": interface.ip,
                            "mask": mask,
                            "hsrp_virtual_ip":
                                interface.hsrp_virtual_ip,
                            "hsrp_state":
                                interface.hsrp_state,
                            "hsrp_priority":
                                interface.hsrp_priority
                        }
                    )

        #
        # Remove exact duplicates.
        #
        unique = {}

        for interface in all_interfaces:

            key = (
                interface.get("device"),
                interface.get("interface"),
                interface.get("vrf"),
                interface.get("ip"),
                interface.get("mask"),
                interface.get("hsrp_virtual_ip")
            )

            unique[key] = interface

        all_interfaces = list(
            unique.values()
        )

        #
        # Write normalized export.
        #
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
                all_interfaces,
                f,
                indent=4
            )

        return all_interfaces
