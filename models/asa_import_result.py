from dataclasses import dataclass, field

from models.bgp_route import BGPRoute
from models.nat_rule import NATRule


@dataclass
class ASAImportResult:

    nat_rules: list[NATRule] = field(default_factory=list)

    bgp_routes: list[BGPRoute] = field(default_factory=list)

    interfaces: list = field(default_factory=list)

    objects: list = field(default_factory=list)

    object_groups: list = field(default_factory=list)

    acl_rules: list = field(default_factory=list)

    routes: list = field(default_factory=list)

    bgp_neighbors: list = field(default_factory=list)

    vpn_tunnels: list = field(default_factory=list)