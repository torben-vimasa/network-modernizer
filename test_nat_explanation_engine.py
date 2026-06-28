from engines.nat_engine import NATEngine
from models.nat_rule import NATRule
from models.packet import Packet

packet = Packet(
    source="172.27.210.20",
    destination="100.72.36.70"
)

rule = NATRule(
    name="KMS_SNAT",
    source_original="172.27.210.20",
    source_translated="10.255.255.17",
    destination_original="100.72.36.70",
    destination_translated="100.72.36.70"
)

engine = NATEngine(
    rules=[rule]
)

translated_packet, result = engine.translate(packet)

print()
print("NAT Explanation")
print("=" * 50)

print(result.explanation)

print()

print("Confidence")
print("----------------")

print(result.explanation.confidence.level)
print(result.explanation.confidence.score)
print(result.explanation.confidence.reason)