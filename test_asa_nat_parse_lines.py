from loaders.asa_config_loader import ASAConfigLoader
from parsers.asa_nat_parser import ASANATParser


loader = ASAConfigLoader()
parser = ASANATParser()

lines = loader.load("data/asa_nat_sample.txt")
rules = parser.parse_lines(lines)

print()
print("ASA NAT parse_lines")
print("=" * 50)
print("Rules:", len(rules))

for rule in rules:
    print(rule)