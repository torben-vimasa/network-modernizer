from parsers.asa_nat_parser import ASANATParser

from engines.nat_engine import NATEngine

from models.packet import Packet


parser = ASANATParser()

line = (
    "nat (inside,outside) "
    "source static CLIENT_REAL CLIENT_NAT"
)

rule = parser.parse_line(line)

engine = NATEngine(
    rules=[
        rule
    ]
)

packet = Packet(
    source="CLIENT_REAL",
    destination="100.72.36.70"
)

translated, result = engine.translate(packet)

print()
print("NAT Pipeline")
print("=" * 60)

print()

print("Parser")

print(rule)

print()

print("Engine")

print(result.reason)

print()

print("Original Packet")

print(packet)

print()

print("Translated Packet")

print(translated)