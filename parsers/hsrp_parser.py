from models.hsrp_state import HSRPState


class HSRPParser:

    def parse(self, lines, device="UnknownRouter"):

        states = []
        current = None

        for raw in lines:
            line = raw.strip()

            if line.startswith("Vlan") and "Group" in line:
                if current:
                    states.append(current)

                interface = line.split()[0]

                current = HSRPState(
                    device=device,
                    interface=interface
                )

            if not current:
                continue

            if "Local state is Active" in line:
                current.state = "Active"

            elif "Local state is Standby" in line:
                current.state = "Standby"

            elif line.startswith("Virtual IP address is "):
                current.virtual_ip = line.split()[4]

            elif line.startswith("Active router is "):
                current.active_router = line.replace("Active router is ", "").split(",")[0].strip()

            elif line.startswith("Standby router is "):
                current.standby_router = line.replace("Standby router is ", "").split(",")[0].strip()

        if current:
            states.append(current)
        
        unique = {}

        for state in states:
            key = (
                state.device,
                state.interface,
                state.virtual_ip
            )
            unique[key] = state

        return list(unique.values())
    