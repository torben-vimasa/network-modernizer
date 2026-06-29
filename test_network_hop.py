from models.network_hop import NetworkHop


router_hop = NetworkHop(
    hop_number=1,
    hop_type="router",
    device="RGDCPe1",
    vrf="CS",
    route="100.72.36.64/27",
    next_hop="10.255.255.17",
    reason="Matched route"
)

router_hop = NetworkHop(
    hop_number=1,
    hop_type="router",
    device="RGDCPe1",
    vrf="CS",
    route="100.72.36.64/27",
    next_hop="10.255.255.17",
    reason="Matched route",

    acl_rule="access-in-CS:467",
    nat_rule="KMS_SNAT",
    route_lookup="100.72.36.64/27",
    policy="permit"
)

firewall_hop = NetworkHop(
    hop_number=2,
    hop_type="firewall",
    device="BHASA1",
    context="BDK-Mgmt",
    ingress_interface="CS",
    egress_interface="Transit",
    ip="10.255.255.17",
    subnet="10.255.255.16/28",

    acl_rule="access-in-CS:467",
    nat_rule="KMS_SNAT",
    route_lookup="100.72.36.64/27",
    policy="permit",

    reason="Next-hop resolved to ASA interface"
)

print()
print("NetworkHop Test")
print("=" * 50)

print(router_hop)
print(firewall_hop)