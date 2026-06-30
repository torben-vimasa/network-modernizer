class TraceReporter:

    def __init__(self, result):
        self.result = result

    def print_console(self):

        print()
        print("TRACE REPORT")
        print("=" * 60)

        self._print_network_path()
        self._print_decisions()
        self._print_trace_log()

    def _print_network_path(self):

        print()
        print("NETWORK PATH")
        print("-" * 60)

        if not self.result or not self.result.network_hops:
            print("No network hops")
            return

        for hop in self.result.network_hops:

            print()
            print(f"Hop {hop.hop_number}: {hop.hop_type.upper()}")

            if hop.device:
                print(f"Device   : {hop.device}")

            if hop.context:
                print(f"Context  : {hop.context}")

            if hop.vrf:
                print(f"VRF      : {hop.vrf}")

            if hop.ingress_interface:
                print(f"Ingress  : {hop.ingress_interface}")

            if hop.egress_interface:
                print(f"Egress   : {hop.egress_interface}")

            if hop.route:
                print(f"Route    : {hop.route}")

            if hop.next_hop:
                print(f"Next hop : {hop.next_hop}")

            if hop.reason:
                print(f"Reason   : {hop.reason}")

    def _print_decisions(self):

        print()
        print("DECISIONS")
        print("-" * 60)

        if not self.result or not self.result.network_hops:
            print("No decisions")
            return

        for hop in self.result.network_hops:

            if hop.hop_type == "router":
                print(f"✓ Router route lookup on {hop.device}: {hop.route}")

            if hop.hop_type == "firewall":
                if hop.policy:
                    print(f"✓ Firewall policy: {hop.policy}")

                if hop.acl_rule:
                    print(f"✓ ACL rule: {hop.acl_rule}")

                if hop.nat_rule:
                    print(f"✓ NAT rule: {hop.nat_rule}")

                if hop.route_lookup:
                    print(f"✓ Firewall route lookup: {hop.route_lookup}")

                if hop.egress_interface:
                    print(f"✓ Firewall egress: {hop.egress_interface}")

    def _print_trace_log(self):

        print()
        print("TRACE LOG")
        print("-" * 60)

        explanation = self.result.explanation

        steps = getattr(explanation, "steps", None)

        if not steps:
            print(explanation)
            return

        for index, step in enumerate(steps, start=1):
            print(f"{index:02d}. {step}")