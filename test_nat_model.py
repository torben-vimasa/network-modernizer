from models.nat_rule import NATRule
from models.nat_result import NATResult


rule = NATRule(
    name="KMS_SNAT",
    source_original="172.27.210.20",
    source_translated="10.255.255.17",
    destination_original="100.72.36.70",
    destination_translated="100.72.36.70",
    direction="inside,outside",
    section="manual",
    raw="nat ..."
)

result = NATResult(
    matched=True,
    rule=rule,
    source_before="172.27.210.20",
    source_after="10.255.255.17",
    destination_before="100.72.36.70",
    destination_after="100.72.36.70",
    reason="Matched static source NAT"
)

print()
print("NAT Model Test")
print("=" * 50)
print(result)