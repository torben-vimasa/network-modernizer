from api.digital_twin import DigitalTwin


dt = DigitalTwin()

dt.load_router(
    "data/router_raw/OBvDCPe1-20260424.txt"
)

result = dt.trace.resolver.resolve_ip("172.21.2.26")

print()
print("Firewall Next-Hop Resolver")
print("=" * 60)

print("Resolved  :", result.get("resolved"))
print("Method    :", result.get("method"))
print("Router    :", result.get("router"))
print("VRF       :", result.get("vrf"))
print("Interface :", result.get("interface"))
print("Subnet    :", result.get("subnet"))
print("Reason    :", result.get("reason"))
print("Confidence:", result.get("confidence"))

print()
print(result)