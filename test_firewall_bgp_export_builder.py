from builders.firewall_bgp_export_builder import FirewallBGPExportBuilder


neighbors = FirewallBGPExportBuilder().build()

print()
print("Firewall BGP Export Builder")
print("=" * 60)
print("Neighbors:", len(neighbors))
print("Output   : output/firewall_bgp_neighbors.json")

for n in neighbors[:10]:
    print()
    print("Device     :", n.device)
    print("Neighbor   :", n.neighbor)
    print("Remote AS  :", n.remote_as)
    print("Description:", n.description)