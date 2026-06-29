from loaders.asa_config_loader import ASAConfigLoader

from parsers.asa_nat_parser import ASANATParser


class ASAImporter:

    def __init__(self):

        self.loader = ASAConfigLoader()

        self.nat_parser = ASANATParser()

    def import_config(self, filename):

        lines = self.loader.load(filename)

        result = {}

        result["nat_rules"] = self.nat_parser.parse_lines(lines)

        return result