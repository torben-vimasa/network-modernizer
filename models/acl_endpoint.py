from dataclasses import dataclass


@dataclass
class ACLEndpoint:

    endpoint_type: str

    value: str

    def is_any(self):
        return self.endpoint_type == "any"

    def is_host(self):
        return self.endpoint_type == "host"

    def is_object(self):
        return self.endpoint_type == "object"

    def is_group(self):
        return self.endpoint_type == "object-group"

    def is_raw(self):
        return self.endpoint_type == "raw"