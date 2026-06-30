from pathlib import Path

from loaders.asa_config_loader import ASAConfigLoader

from models.asa_import_result import ASAImportResult

from parsers.bgp_parser import BGPParser
from parsers.interface_parser import InterfaceParser
from parsers.route_parser import RouteParser


class RouterImporter:

    def __init__(self):

        self.loader = ASAConfigLoader()

        self.route_parser = RouteParser()
        self.bgp_parser = BGPParser()
        self.interface_parser = InterfaceParser()

    def import_router(self, filename):

        filename = Path(filename)

        lines = self.loader.load(filename)

        result = ASAImportResult()

        result.routes = self.route_parser.parse_router_config(
            filename.stem,
            lines
        )

        result.bgp_routes = self.bgp_parser.parse(
            lines,
            source_router=filename.stem,
            vrf="unknown"
        )

        result.interfaces = self.interface_parser.parse(
            lines,
            device=filename.stem
        )

        return result