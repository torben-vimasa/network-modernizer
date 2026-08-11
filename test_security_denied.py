from api.digital_twin import DigitalTwin


twin = DigitalTwin()

trace = twin.trace.trace(
    source="172.21.64.69",
    destination="172.21.2.103",
    protocol="tcp",
    service="88",
    start={
        "type": "firewall",
        "context": "BDK-Teknik",
        "interface": "Nokia_Jumphosts_DMZ"
    },
    max_hops=20
)


print()
print("=" * 60)
print("TRACE")
print("=" * 60)

print("Status security permitted :", getattr(trace.security, "permitted", None))
print("Reason                    :", getattr(trace.security, "reason", None))

print()
print("=" * 60)
print("SECURITY ASSESSMENT")
print("=" * 60)

assessment = getattr(trace, "security_assessment", None)

if assessment is None:
    print("No security assessment returned")
else:
    print("Classification :", assessment.classification)
    print("Disposition    :", assessment.disposition)
    print("Confidence     :", assessment.confidence)
    print("Message        :", assessment.message)
    print("Device         :", assessment.device)
    print("Interface      :", assessment.interface)
    print("Next hop       :", assessment.next_hop)
    print("Evidence       :", assessment.evidence)