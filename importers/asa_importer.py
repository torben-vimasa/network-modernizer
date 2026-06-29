from loaders.asa_config_loader import ASAConfigLoader

from models.asa_import_result import ASAImportResult

from parsers.asa_nat_parser import ASANATParser
from parsers.bgp_parser import BGPParser


class ASAImporter:

    def __init__(self):

        self.loader = ASAConfigLoader()

        self.nat_parser = ASANATParser()
        self.bgp_parser = BGPParser()

    def import_config(self, filename):

        lines = self.loader.load(filename)

        result = ASAImportResult()

        result.nat_rules = self.nat_parser.parse_lines(lines)

        result.bgp_routes = self.bgp_parser.parse(
            lines,
            source_router=filename,
            vrf="unknown"
        )

        return result