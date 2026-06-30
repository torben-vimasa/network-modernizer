from engines.interface_resolution_engine import InterfaceResolutionEngine


interfaces = [
    {
        "name": "CS",
        "subnet": "10.255.255.16/28"
    },
    {
        "name": "Transit",
        "subnet": "172.21.2.16/28"
    }
]

engine = InterfaceResolutionEngine(interfaces)

result = engine.resolve_egress("172.21.2.26")

print()
print("Interface Resolution Engine")
print("=" * 60)

print(result)