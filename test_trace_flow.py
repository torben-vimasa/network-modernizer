from builders.graph_builder import GraphBuilder
from engines.security_engine import SecurityEngine
from engines.route_engine import RouteEngine


graph = GraphBuilder().build_from_vrf_inventory()

security = SecurityEngine(graph)
routes = RouteEngine()

flow = {
    "source": "172.27.210.20",
    "destination": "SPNS2_Logpoint_100.72.36.70",
    "route_destination": "100.72.36.70",
    "protocol": "object-group",
    "service": "Windows_Logging",
    "router": "RGDCPe1",
    "vrf": "CS",
}

print()
print("Trace Flow Test")
print("=" * 40)

print(f'Source:      {flow["source"]}')
print(f'Destination: {flow["destination"]}')
print(f'Protocol:    {flow["protocol"]}')
print(f'Service:     {flow["service"]}')

security_result = security.is_permitted(
    flow["source"],
    flow["destination"],
    protocol=flow["protocol"],
    service=flow["service"]
)

print()
print("Security")
print("-" * 40)
print(security_result.reason)

if security_result.rule:
    print(security_result.rule.properties["raw"])

if not security_result.permitted:
    print()
    print("Trace stopped: traffic not permitted")
    raise SystemExit

route = routes.lookup(
    flow["router"],
    flow["vrf"],
    flow["route_destination"]
)

print()
print("Routing")
print("-" * 40)

if route:
    print(f'Matched route: {route["prefix"]}')
    print(f'Next hop:      {route["next_hop"]}')
    print(f'Protocol:      {route["protocol"]}')
else:
    print("No route found")