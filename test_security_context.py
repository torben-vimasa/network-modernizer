from api.digital_twin import DigitalTwin


twin = DigitalTwin()

trace = twin.trace_packet(
    source="10.150.146.34",
    destination="157.250.163.241",
    protocol="udp",
    service="sip",
    router="RGDCPe1",
    vrf="bane1"
)


print()
print("=" * 60)
print("TRACE")
print("=" * 60)

print("Status :", trace.status)
print("Reason :", trace.reason)


print()
print("=" * 60)
print("SECURITY ASSESSMENT")
print("=" * 60)

assessment = trace.security_assessment

if assessment is None:
    print("No security assessment")
else:
    print("Classification :", assessment.classification)
    print("Disposition    :", assessment.disposition)
    print("Confidence     :", assessment.confidence)
    print("Message        :", assessment.message)
    print("Device         :", assessment.device)
    print("Interface      :", assessment.interface)
    print("Next hop       :", assessment.next_hop)
    print("Evidence       :", assessment.evidence)