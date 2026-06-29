from parsers.asa_nat_parser import ASANATParser

from engines.nat_engine import NATEngine

from models.packet import Packet


parser = ASANATParser()

rules = parser.parse_file("data/asa_nat_sample.txt")

engine = NATEngine(rules)

packet = Packet(
    source="CLIENT_REAL",
    destination="100.72.36.70"
)

translated, result = engine.translate(packet)

print()
print("NAT File Pipeline")
print("=" * 60)

print()

print("Loaded rules :", len(rules))

print()

print("Match :", result.matched)
print("Reason:", result.reason)

print()

print("Original")
print(packet)

print()

print("Translated")
print(translated)