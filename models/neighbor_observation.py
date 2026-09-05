from dataclasses import dataclass
from typing import Optional


@dataclass
class NeighborObservation:
    """
    Normalized observation of a directly connected network neighbor.

    The model is protocol-neutral so the same representation can later
    be populated from CDP, LLDP or other topology discovery protocols.
    """

    local_device: str
    local_interface: str

    remote_device: str
    remote_interface: str

    remote_ip: Optional[str] = None

    protocol: str = "unknown"

    system_name: Optional[str] = None
    platform: Optional[str] = None
    software: Optional[str] = None

    source_file: Optional[str] = None

    confidence: str = "high"