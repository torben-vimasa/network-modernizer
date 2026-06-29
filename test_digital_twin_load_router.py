from api.digital_twin import DigitalTwin


dt = DigitalTwin()

result = dt.load_router(
    "data/router_raw/OBvDCPe1-20260424.txt"
)

print()
print("DigitalTwin load_router")
print("=" * 60)

print("Routes     :", len(result.routes))
print("BGP routes :", len(result.bgp_routes))
print("Graph nodes:", len(dt.graph.nodes))
print("Graph rels :", len(dt.graph.relationships))