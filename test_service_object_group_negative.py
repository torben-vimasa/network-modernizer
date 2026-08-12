from api.digital_twin import DigitalTwin

t = DigitalTwin()

result = t.security.is_permitted(
    source="172.21.64.69",
    destination="172.21.2.103",
    protocol="tcp",
    service="22",
    context="BDK-Teknik",
    ingress_interface="Nokia_Jumphosts_DMZ"
)

print("Permitted :", result.permitted)
print("Reason    :", result.reason)

if result.rule:
    print("Rule      :", result.rule.name)
    print("Raw       :", result.rule.properties.get("raw"))