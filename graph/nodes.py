from dataclasses import dataclass


@dataclass
class Node:
    id: str
    type: str
    name: str
    properties: dict
    