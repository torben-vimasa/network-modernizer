from loaders.asa_config_loader import ASAConfigLoader
from parsers.asa_nat_parser import ASANATParser
from engines.nat_engine import NATEngine
from models.packet import Packet


loader = ASAConfigLoader()
parser = ASANATParser()

lines = loader.load("data/asa_nat_sample.txt")
rules = parser.parse_lines(lines)

engine = NATEngine(rules)

packet = Packet(
    source="172.27.210.20",
    destination="100.72.36.70"
)

translated, result = engine.translate(packet)

print()
print("ASA Config NAT Pipeline")
print("=" * 60)

print("Lines :", len(lines))
print("Rules :", len(rules))
print("Match :", result.matched)
print("Reason:", result.reason)

print()
print("Original")
print(packet)

print()
print("Translated")
print(translated)