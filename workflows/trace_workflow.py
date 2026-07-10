from engines.resolver_engine import ResolverEngine
from engines.topology_engine import TopologyEngine
from engines.traversal_engine_factory import TraversalEngineFactory

from models.explanation import Explanation
from models.firewall_hop import FirewallHop
from models.hop import Hop
from models.network_hop import NetworkHop
from models.packet import Packet
from models.route_result import RouteResult
from models.trace_result import TraceResult
from models.traversal_state import TraversalState


class TraceWorkflow:

    def __init__(self, twin):
        self.twin = twin
        self.topology = TopologyEngine(twin.graph)
        self.resolver = ResolverEngine(twin.graph)
        self.factory = TraversalEngineFactory(twin)

    def trace(
        self,
        source,
        destination=None,
        protocol=None,
        service=None,
        router=None,
        vrf=None,
        route_destination=None,
        max_hops=20,
        stop_on_destination=True
    ):

        packet = self._build_packet(
            source=source,
            destination=destination,
            protocol=protocol,
            service=service,
            router=router,
            vrf=vrf,
            route_destination=route_destination
        )

        source = packet.source
        destination = packet.destination
        protocol = packet.protocol
        service = packet.service

        router = packet.current_router or router
        vrf = packet.current_vrf or vrf
        route_destination = route_destination or packet.destination

        explanation = Explanation()
        packet.add_history("Trace started")

        state = TraversalState(
            router=router,
            vrf=vrf,
            destination=route_destination,
            ingress_interface=getattr(
                packet,
                "ingress_interface",
                None
            ),
            phase="routing",
            packet=packet
        )

        #
        # Existing global security evaluation.
        # This remains unchanged during the TraceState refactor.
        #
        security = self.twin.security.is_permitted(
            source,
            destination,
            protocol,
            service
        )

        state.security = security

        explanation.add(
            f"ACL decision: {security.reason}"
        )

        if not security.permitted:
            state.mark_finished(
                reason=security.reason
            )

            return self._build_result(
                state=state,
                explanation=explanation
            )

        #
        # Existing global NAT evaluation.
        # This also remains unchanged during this refactor.
        #
        translated_packet, nat_result = self.twin.nat.translate(
            packet
        )

        explanation.add(
            f"NAT decision: {nat_result.reason}"
        )

        if nat_result.matched:
            explanation.add(
                f"NAT source: "
                f"{nat_result.source_before} -> "
                f"{nat_result.source_after}"
            )

            explanation.add(
                f"NAT destination: "
                f"{nat_result.destination_before} -> "
                f"{nat_result.destination_after}"
            )

        state.packet = translated_packet

        for hop_number in range(1, max_hops + 1):

            if state.finished:
                break

            if not state.has_valid_routing_start():
                reason = (
                    "Trace stopped: missing router, "
                    "VRF or route destination"
                )

                explanation.add(reason)
                state.mark_finished(reason)
                break

            state.ingress_interface = getattr(
                state.packet,
                "ingress_interface",
                None
            )

            visit_key = state.key()

            if visit_key in state.visited:
                reason = (
                    f"Trace stopped: loop detected at "
                    f"{state.router} VRF {state.vrf}"
                )

                explanation.add(reason)
                state.mark_finished(reason)
                break

            state.visited.add(visit_key)

            route, route_result = self._trace_router(
                current_router=state.router,
                current_vrf=state.vrf,
                route_destination=state.destination,
                hops=state.hops,
                network_hops=state.network_hops,
                explanation=explanation
            )

            state.last_route_result = route_result

            if not route:
                state.mark_finished(
                    reason=(
                        f"No route matched on "
                        f"{state.router} VRF {state.vrf}"
                    )
                )
                break

            state.packet.next_hop = route["next_hop"]

            next_device, resolution = self._resolve_router_next_hop(
                current_router=state.router,
                current_vrf=state.vrf,
                next_hop=route["next_hop"],
                explanation=explanation
            )

            if self._is_firewall_resolution(resolution):

                traversal = self._trace_firewall(
                    resolution=resolution,
                    source=source,
                    route_destination=state.destination,
                    protocol=protocol,
                    service=service,
                    firewall_hops=state.firewall_hops,
                    network_hops=state.network_hops,
                    explanation=explanation
                )

                state.security = (
                    traversal.security
                    or state.security
                )

                if traversal.output_packet:
                    state.packet = traversal.output_packet

                if (
                    stop_on_destination
                    and getattr(
                        traversal,
                        "destination_reached",
                        False
                    )
                ):
                    reason = (
                        f"Destination reached via firewall "
                        f"route {traversal.route}"
                    )

                    explanation.add(reason)

                    state.mark_finished(
                        reason=reason,
                        destination_reached=True
                    )
                    break

                if self._continue_from_firewall_target(
                    state=state,
                    traversal=traversal,
                    fallback_vrf=vrf,
                    explanation=explanation
                ):
                    continue

                reason = (
                    "Trace stopped after firewall traversal: "
                    "missing next-router inventory"
                )

                explanation.add(reason)
                state.mark_finished(reason)
                break

            if next_device:
                self._continue_to_router(
                    state=state,
                    next_device=next_device,
                    hop_number=hop_number,
                    explanation=explanation
                )
                continue

            reason = (
                f"Trace stopped: next hop "
                f"{route['next_hop']} could not be "
                f"directly resolved"
            )

            explanation.add(reason)

            if resolution:
                explanation.add(
                    f"Resolver: "
                    f"{resolution.get('reason')} "
                    f"({resolution.get('confidence')} confidence)"
                )

            state.mark_finished(reason)
            break

        return self._build_result(
            state=state,
            explanation=explanation
        )

    def _build_packet(
        self,
        source,
        destination,
        protocol,
        service,
        router,
        vrf,
        route_destination
    ):

        if isinstance(source, Packet):
            packet = source

            if packet.current_router is None:
                packet.current_router = router

            if packet.current_vrf is None:
                packet.current_vrf = vrf

            return packet

        return Packet(
            source=source,
            destination=route_destination or destination,
            protocol=protocol,
            service=service,
            current_router=router,
            current_vrf=vrf
        )

    def _trace_router(
        self,
        current_router,
        current_vrf,
        route_destination,
        hops,
        network_hops,
        explanation
    ):

        route = self.twin.route.lookup(
            current_router,
            current_vrf,
            route_destination
        )

        if not route:
            explanation.add(
                f"No route matched on "
                f"{current_router} VRF {current_vrf}"
            )

            return None, RouteResult(
                matched=False,
                hop=None
            )

        hop_number = len(hops) + 1

        explanation.add(
            f"Hop {hop_number}: "
            f"{current_router} VRF {current_vrf} "
            f"matched route {route['prefix']}"
        )

        explanation.add(
            f"Hop {hop_number}: "
            f"next hop {route['next_hop']}"
        )

        hop = Hop(
            router=current_router,
            vrf=current_vrf,
            route=route["prefix"],
            next_hop=route["next_hop"]
        )

        hops.append(hop)

        network_hops.append(
            NetworkHop(
                hop_number=len(network_hops) + 1,
                hop_type="router",
                device=current_router,
                vrf=current_vrf,
                route=route["prefix"],
                next_hop=route["next_hop"],
                reason="Matched route"
            )
        )

        return route, RouteResult(
            matched=True,
            hop=hop
        )

    def _resolve_router_next_hop(
        self,
        current_router,
        current_vrf,
        next_hop,
        explanation
    ):

        next_device = self.topology.resolve_router(
            next_hop
        )

        forwarding = self.factory.get_engine(
            "Forwarding"
        )

        forward = None
        resolution = None

        if forwarding:
            forward = forwarding.resolve_next_hop(
                current_device=current_router,
                next_hop=next_hop
            )

            if forward:
                explanation.add(
                    f"Forwarding: {forward.reason}"
                )

        if (
            not next_device
            and forward
            and forward.resolved
        ):

            if forward.device_type in [
                "Firewall",
                "Context"
            ]:
                resolution = (
                    self._resolution_from_forwarding(
                        forward=forward,
                        next_hop=next_hop
                    )
                )

            else:
                next_device = {
                    "router": forward.device,
                    "vrf": current_vrf,
                    "interface": forward.interface
                }

        if not next_device and not resolution:
            resolution = self.resolver.resolve_ip(
                next_hop
            )

        return next_device, resolution

    def _resolution_from_forwarding(
        self,
        forward,
        next_hop
    ):

        node = self.twin.graph.find(
            "ASAInterface",
            forward.interface
        )

        context = None

        if node:
            context = (
                node.properties.get("context")
                or node.properties.get("device")
            )

        interface_name = forward.interface

        if ":" in interface_name:
            interface_name = interface_name.split(
                ":",
                1
            )[1]

        return {
            "resolved": True,
            "method": "asa_interface",
            "firewall": forward.device,
            "context": context,
            "interface": interface_name,
            "ip": next_hop,
            "subnet": None,
            "reason": forward.reason,
            "confidence": "high"
        }

    def _is_firewall_resolution(
        self,
        resolution
    ):

        return bool(
            resolution
            and resolution.get("resolved")
            and resolution.get("method")
            == "asa_interface"
        )

    def _trace_firewall(
        self,
        resolution,
        source,
        route_destination,
        protocol,
        service,
        firewall_hops,
        network_hops,
        explanation
    ):

        fw_hop = FirewallHop(
            firewall=resolution.get("firewall"),
            context=resolution.get("context"),
            ingress_interface=resolution.get("interface"),
            ip=resolution.get("ip"),
            subnet=resolution.get("subnet"),
            reason="Next-hop resolved to ASA interface"
        )

        firewall_hops.append(fw_hop)

        engine = self.factory.get_engine(
            "Firewall"
        )

        traversal = engine.traverse(
            fw_hop,
            Packet(
                source=source,
                destination=route_destination,
                protocol=protocol,
                service=service
            )
        )

        security_rule_id = None

        if (
            traversal.security
            and getattr(
                traversal.security,
                "rule_id",
                None
            )
        ):
            security_rule_id = str(
                traversal.security.rule_id
            )

        nat_rule_name = None

        if (
            traversal.nat
            and traversal.nat.rule
        ):
            nat_rule_name = (
                traversal.nat.rule.name
            )

        network_hops.append(
            NetworkHop(
                hop_number=len(network_hops) + 1,
                hop_type="firewall",
                device=traversal.firewall,
                context=traversal.context,
                ingress_interface=(
                    traversal.ingress_interface
                ),
                egress_interface=(
                    traversal.egress_interface
                ),
                ip=resolution.get("ip"),
                subnet=resolution.get("subnet"),
                route=traversal.route,
                next_hop=traversal.next_hop,
                reason=traversal.reason,
                acl_rule=security_rule_id,
                nat_rule=nat_rule_name,
                route_lookup=traversal.route,
                policy=(
                    "permit"
                    if traversal.permitted
                    else "deny"
                )
            )
        )

        explanation.add(
            f"Trace reached ASA interface "
            f"{resolution.get('context')}:"
            f"{resolution.get('interface')}"
        )

        explanation.add(
            f"Firewall traversal: "
            f"{traversal.reason}"
        )

        explanation.add(
            f"Firewall egress: "
            f"{traversal.egress_interface}"
        )

        explanation.add(
            f"Firewall next-hop: "
            f"{traversal.next_hop}"
        )

        return traversal

    def _continue_from_firewall_target(
        self,
        state,
        traversal,
        fallback_vrf,
        explanation
    ):

        target = getattr(
            traversal,
            "target",
            None
        )

        if target and target.resolved:
            state.set_router_target(
                router=target.device_name,
                vrf=target.vrf or fallback_vrf,
                ingress_interface=target.interface
            )

            explanation.add(
                f"Trace continues to "
                f"{target.device_type} "
                f"{state.router} VRF {state.vrf}"
            )

            return True

        next_device = traversal.next_device

        if (
            next_device
            and next_device.get("resolved")
        ):
            method = next_device.get("method")

            if method in [
                "router_inventory",
                "topology_connected_to"
            ]:
                state.set_router_target(
                    router=next_device.get("router"),
                    vrf=(
                        next_device.get("vrf")
                        or fallback_vrf
                    ),
                    ingress_interface=(
                        next_device.get("interface")
                    )
                )

                explanation.add(
                    f"Trace continues to router "
                    f"{state.router} VRF {state.vrf}"
                )

                return True

            explanation.add(
                f"Firewall next-hop resolution: "
                f"{next_device.get('reason')}"
            )

            explanation.add(
                f"Firewall next-hop resolution "
                f"method: {method}"
            )

            explanation.add(
                f"Firewall next-hop resolution "
                f"confidence: "
                f"{next_device.get('confidence')}"
            )

        return False

    def _continue_to_router(
        self,
        state,
        next_device,
        hop_number,
        explanation
    ):

        explanation.add(
            f"Hop {hop_number}: next hop resolved "
            f"to {next_device['router']} "
            f"VRF {next_device['vrf']}"
        )

        state.set_router_target(
            router=next_device["router"],
            vrf=next_device["vrf"],
            ingress_interface=(
                next_device.get("interface")
            )
        )

    def _build_result(
        self,
        state,
        explanation
    ):

        return TraceResult(
            security=state.security,
            route=state.last_route_result,
            hops=state.hops,
            firewall_hops=state.firewall_hops,
            network_hops=state.network_hops,
            explanation=explanation
        )