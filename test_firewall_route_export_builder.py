from builders.firewall_route_export_builder import FirewallRouteExportBuilder


routes = FirewallRouteExportBuilder().build()

print()
print("Firewall Route Export Builder")
print("=" * 60)
print("Routes:", len(routes))
print("Output: output/firewall_routes.json")

for r in routes:
    if r.prefix in ["100.72.36.64/27", "100.72.0.0/16"]:
        print()
        print("Router :", r.router)
        print("Context:", r.vrf)
        print("Route  :", r.prefix)
        print("Egress :", getattr(r, "egress_interface", None))
        print("NextHop:", r.next_hop)