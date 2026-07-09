from api.digital_twin import DigitalTwin

dt = DigitalTwin()

for ip in [
    "172.27.210.20",
    "172.21.2.62"
]:
    print()
    print(ip)
    print("=" * 60)
    print(dt.trace.resolver.resolve_source(ip))