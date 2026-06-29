from models.bgp_route import BGPRoute
from models.bgp_result import BGPResult


route = BGPRoute(
    prefix="100.72.36.64/27",
    next_hop="10.255.255.17",
    as_path="65020 65030",
    local_pref=100,
    med=0,
    origin="i",
    source_router="RGDCPe1",
    vrf="CS",
    raw="*> 100.72.36.64/27 10.255.255.17 0 100 0 65020 i"
)

result = BGPResult(
    matched=True,
    route=route,
    reason="Best BGP path selected"
)

print()
print("BGP Model Test")
print("=" * 50)
print(result)