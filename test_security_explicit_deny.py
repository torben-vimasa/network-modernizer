from api.digital_twin import DigitalTwin


twin = DigitalTwin()

trace = twin.trace.trace(
    source="192.0.2.10",
    destination="192.0.2.20",
    protocol="tcp",
    service="12345",
    start={
        "type": "firewall",
        "context": "BDK-DSB",
        "interface": "inside"
    },
    max_hops=20
)


print()
print("=" * 60)
print("TRACE SECURITY")
print("=" * 60)

security = trace.security

print("Permitted :", getattr(security, "permitted", None))
print("Reason    :", getattr(security, "reason", None))

rule = getattr(security, "rule", None)

if rule:
    print("Rule      :", rule.name)
    print("Action    :", rule.properties.get("action"))
    print("Sequence  :", rule.properties.get("sequence"))
    print("Raw       :", rule.properties.get("raw"))


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