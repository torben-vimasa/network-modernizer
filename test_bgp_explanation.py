from models.bgp_explanation import BGPExplanation
from models.confidence import Confidence


explanation = BGPExplanation(
    matched=True,
    reason="Best BGP route selected by longest prefix match",
    prefix="100.72.36.64/27",
    next_hop="10.255.255.17",
    as_path="65020 65030",
    local_pref=100,
    med=0,
    origin="i",
    vrf="CS",
    confidence=Confidence(
        level="high",
        score=1.0,
        reason="BGP route matched destination prefix"
    )
)

print()
print("BGP Explanation Test")
print("=" * 50)
print(explanation)