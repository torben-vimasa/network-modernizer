from models.confidence import Confidence
from models.nat_explanation import NATExplanation


explanation = NATExplanation(
    matched=True,
    reason="Matched static source NAT",
    source_before="172.27.210.20",
    source_after="10.255.255.17",
    destination_before="100.72.36.70",
    destination_after="100.72.36.70",
    rule_name="TEST_SNAT",
    direction="inside,outside",
    section="manual",
    confidence=Confidence(
        level="high",
        score=1.0,
        reason="NAT rule matched exact source and destination"
    )
)

print()
print("NAT Explanation Test")
print("=" * 50)
print(explanation)