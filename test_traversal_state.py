from models.traversal_state import TraversalState


state1 = TraversalState(
    router="RGDCPe1",
    vrf="CS",
    ingress_interface="Vlan851",
    destination="100.72.36.70"
)

state2 = TraversalState(
    router="RGDCPe1",
    vrf="CS",
    ingress_interface="Vlan859",
    destination="100.72.36.70"
)

print()
print("Traversal State")
print("=" * 60)

print("State 1:", state1.key())
print("State 2:", state2.key())
print("Same?  :", state1.key() == state2.key())