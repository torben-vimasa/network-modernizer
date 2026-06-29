from pathlib import Path

from loaders.asa_config_loader import ASAConfigLoader

from models.asa_import_result import ASAImportResult

from parsers.route_parser import RouteParser
from parsers.bgp_parser import BGPParser


class RouterImporter:

    def __init__(self):

        self.loader = ASAConfigLoader()

        self.route_parser = RouteParser()
        self.bgp_parser = BGPParser()

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

        return result