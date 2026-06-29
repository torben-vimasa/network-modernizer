from pathlib import Path

from importers.router_importer import RouterImporter
from importers.asa_importer import ASAImporter


class ImportDispatcher:

    def __init__(self):

        self.router = RouterImporter()
        self.asa = ASAImporter()

    def import_file(self, filename):

        filename = Path(filename)

        with open(filename, encoding="utf-8", errors="ignore") as f:
            first = f.read(8000)

        # Cisco ASA
        if "ASA Version" in first or "ASA" in first:
            return self.asa.import_config(filename)

        # Cisco IOS-XR
        if "show bgp" in first:
            return self.router.import_router(filename)

        if "hostname " in first:
            return self.router.import_router(filename)

        if "BGP routing table information" in first:
            return self.router.import_router(filename)

        return None