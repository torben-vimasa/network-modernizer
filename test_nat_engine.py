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
    name="KMS_SNAT",
    source_original="172.27.210.20",
    source_translated="10.255.255.17",
    destination_original="100.72.36.70",
    destination_translated="100.72.36.70",
    raw="nat ..."
)

engine = NATEngine(
    rules=[
        rule
    ]
)

result = engine.translate(packet)

print()
print("NAT Engine Test")
print("=" * 50)

print("Matched :", result.matched)
print("Reason  :", result.reason)
print("Source  :", result.source_before, "->", result.source_after)
print("Dest    :", result.destination_before, "->", result.destination_after)