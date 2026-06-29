import re

from models.bgp_route import BGPRoute


class BGPParser:

    ROUTE_LINE = re.compile(
        r"^\s*(?P<status>[\*>sidrh ]+)"
        r"(?P<prefix>\d+\.\d+\.\d+\.\d+/\d+)\s+"
        r"(?P<next_hop>\d+\.\d+\.\d+\.\d+)\s+"
        r"(?P<rest>.*)$"
    )

    def parse(self, lines, source_router=None, vrf=None):

        routes = []

        for line in lines:
            route = self.parse_line(
                line,
                source_router=source_router,
                vrf=vrf
            )

            if route:
                routes.append(route)

        return routes

    def parse_line(self, line, source_router=None, vrf=None):

        line = line.rstrip()

        match = self.ROUTE_LINE.match(line)

        if not match:
            return None

        rest = match.group("rest").split()

        local_pref = None
        med = None
        origin = None
        as_path = None

        if rest:
            origin = rest[-1]

        numbers = [x for x in rest if x.isdigit()]

        if len(numbers) >= 1:
            med = int(numbers[0])

        if len(numbers) >= 2:
            local_pref = int(numbers[1])

        if len(numbers) >= 4:
            as_path = " ".join(numbers[3:])

        return BGPRoute(
            prefix=match.group("prefix"),
            next_hop=match.group("next_hop"),
            as_path=as_path,
            local_pref=local_pref,
            med=med,
            origin=origin,
            source_router=source_router,
            vrf=vrf,
            raw=line
        )