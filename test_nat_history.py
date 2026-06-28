from engines.nat_engine import NATEngine
from models.nat_rule import NATRule
from models.packet import Packet

packet = Packet(
    source="172.27.210.20",
    destination="100.72.36.70",
    protocol="tcp",
    service="443"
)

rule = NATRule(
    name="TEST_SNAT",
    source_original="172.27.210.20",
    source_translated="10.255.255.17"
)

engine = NATEngine([rule])

translated, result = engine.translate(packet)

print()
print("Packet History")
print("=" * 50)

for entry in translated.history:
    print(entry)