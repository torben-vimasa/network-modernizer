from engines.bgp_engine import BGPEngine
from models.bgp_route import BGPRoute


routes = [
    BGPRoute(
        prefix="100.72.0.0/16",
        next_hop="10.255.255.1",
        vrf="CS"
    ),
    BGPRoute(
        prefix="100.72.36.64/27",
        next_hop="10.255.255.17",
        vrf="CS"
    )
]

engine = BGPEngine(routes)

result = engine.lookup(
    destination="100.72.36.70",
    vrf="CS"
)

print()
print("BGP Engine Test")
print("=" * 50)

print("Matched :", result.matched)
print("Reason  :", result.reason)
print("Prefix  :", result.route.prefix)
print("NextHop :", result.route.next_hop)