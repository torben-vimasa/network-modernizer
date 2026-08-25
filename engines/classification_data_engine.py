from pathlib import Path
import ipaddress
import yaml


class ClassificationDataEngine:

    def __init__(
        self,
        base_path="data/classification"
    ):

        self.base_path = Path(
            base_path
        )

        self.domains = {}
        self.networks = []
        self.services = []
        self.ownership = []

        self._load()

    def _load(
        self
    ):

        self.domains = self._load_yaml(
            "domains.yaml"
        ).get(
            "domains",
            {}
        )

        self.networks = self._load_yaml(
            "networks.yaml"
        ).get(
            "networks",
            []
        )

        self.services = self._load_yaml(
            "services.yaml"
        ).get(
            "services",
            []
        )

        self.ownership = self._load_yaml(
            "ownership.yaml"
        ).get(
            "ownership",
            []
        )

        self._prepare_networks()

    def _load_yaml(
        self,
        filename
    ):

        path = (
            self.base_path
            / filename
        )

        if not path.exists():
            return {}

        with path.open(
            "r",
            encoding="utf-8"
        ) as handle:

            data = yaml.safe_load(
                handle
            )

        if data is None:
            return {}

        return data

    def _prepare_networks(
        self
    ):

        prepared = []

        for item in self.networks:

            network_value = item.get(
                "network"
            )

            if not network_value:
                continue

            try:

                network = ipaddress.ip_network(
                    str(network_value),
                    strict=False
                )

            except ValueError:
                continue

            prepared.append(
                {
                    "network": network,
                    "data": item
                }
            )

        #
        # Longest-prefix match first.
        #
        prepared.sort(
            key=lambda item: (
                item["network"].version,
                item["network"].prefixlen
            ),
            reverse=True
        )

        self.networks = prepared

    def find_service(
        self,
        name
    ):

        if not name:
            return None

        candidate = self._normalize(
            name
        )

        for item in self.services:

            names = [
                item.get(
                    "name"
                )
            ]

            names.extend(
                item.get(
                    "aliases",
                    []
                )
            )

            for value in names:

                if (
                    self._normalize(
                        value
                    )
                    == candidate
                ):

                    return item

        return None

    def find_ownership(
        self,
        name=None,
        addresses=None
    ):

        addresses = addresses or []

        normalized_name = (
            self._normalize(
                name
            )
            if name
            else None
        )

        normalized_addresses = {
            str(value).strip()
            for value in addresses
            if value
        }

        #
        # First try exact system/name match.
        #
        if normalized_name:

            for item in self.ownership:

                item_name = (
                    item.get(
                        "name"
                    )
                )

                if (
                    item_name
                    and self._normalize(
                        item_name
                    ) == normalized_name
                ):

                    return item

                for alias in item.get(
                    "aliases",
                    []
                ):

                    if (
                        self._normalize(
                            alias
                        )
                        == normalized_name
                    ):

                        return item

        #
        # Then exact address match.
        #
        if normalized_addresses:

            for item in self.ownership:

                item_addresses = {
                    str(value).strip()
                    for value
                    in item.get(
                        "addresses",
                        []
                    )
                    if value
                }

                if (
                    normalized_addresses
                    & item_addresses
                ):

                    return item

        return None

    def find_network(
        self,
        addresses
    ):

        if not addresses:
            return None

        candidates = []

        for value in addresses:

            if not value:
                continue

            try:

                if "/" in str(value):

                    address = ipaddress.ip_network(
                        str(value),
                        strict=False
                    ).network_address

                else:

                    address = ipaddress.ip_address(
                        str(value)
                    )

            except ValueError:
                continue

            candidates.append(
                address
            )

        for item in self.networks:

            network = item[
                "network"
            ]

            for address in candidates:

                if (
                    address.version
                    != network.version
                ):
                    continue

                if address in network:

                    return item[
                        "data"
                    ]

        return None

    def domain_info(
        self,
        domain
    ):

        if not domain:
            return None

        return self.domains.get(
            str(domain)
        )

    def statistics(
        self
    ):

        return {
            "domains": len(
                self.domains
            ),
            "networks": len(
                self.networks
            ),
            "services": len(
                self.services
            ),
            "ownership": len(
                self.ownership
            )
        }

    def _normalize(
        self,
        value
    ):

        if value is None:
            return ""

        return (
            str(value)
            .strip()
            .lower()
        )