from builders.router_route_table_export_builder import RouterRouteTableExportBuilder

routes = RouterRouteTableExportBuilder().build()

print()
print("Router Runtime Route Export Builder")
print("=" * 60)
print("Routes:", len(routes))
print("Output: output/routes_runtime.json")

for r in routes:
    if (
        r.router == "RGDCPe1"
        and r.vrf == "SPNS2-TRANSIT-JTTN"
        and r.prefix == "100.72.36.64/27"
    ):
        print("MATCH:", r)