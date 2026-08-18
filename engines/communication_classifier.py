import json
from pathlib import Path


class CommunicationClassifier:

    def __init__(
        self,
        knowledge_file=Path(
            "knowledge/service_semantics.json"
        )
    ):
        self.knowledge_file = Path(
            knowledge_file
        )

        self.semantics = (
            self._load_semantics()
        )


    def _load_semantics(self):

        if not self.knowledge_file.exists():
            return []

        with open(
            self.knowledge_file,
            encoding="utf-8"
        ) as f:
            return json.load(f)


    def classify(self, communication):

        classifications = []

        for service in communication.get(
            "services",
            []
        ):

            result = self._classify_service(
                service
            )

            if result:
                classifications.append(
                    result
                )

        return {
            "classifications": (
                self._deduplicate(
                    classifications
                )
            ),
            "evidence": self._build_evidence(
                communication
            )
        }


    def _classify_service(self, service):

        protocol = str(
            service.get("protocol") or ""
        ).lower()

        service_name = str(
            service.get("service") or ""
        ).lower()

        candidates = []

        #
        # Service may itself be a numeric port.
        #
        if service_name.isdigit():
            candidates.append(
                service_name
            )

        #
        # Object names such as tcp_631.
        #
        if "_" in service_name:

            suffix = service_name.rsplit(
                "_",
                1
            )[-1]

            if suffix.isdigit():
                candidates.append(
                    suffix
                )

        for semantic in self.semantics:

            expected_protocol = str(
                semantic.get(
                    "protocol",
                    ""
                )
            ).lower()

            if (
                expected_protocol
                and protocol not in [
                    expected_protocol,
                    "object",
                    "object-group"
                ]
            ):
                continue

            service_names = [
                str(x).lower()
                for x in semantic.get(
                    "service_names",
                    []
                )
            ]

            ports = [
                str(x)
                for x in semantic.get(
                    "ports",
                    []
                )
            ]

            name_match = (
                service_name
                and service_name
                in service_names
            )

            port_match = any(
                candidate in ports
                for candidate in candidates
            )

            if not (
                name_match
                or port_match
            ):
                continue

            return {
                "protocol": protocol,
                "observed_service": (
                    service.get("service")
                ),
                "service": semantic[
                    "classification"
                ].get("service"),
                "domain": semantic[
                    "classification"
                ].get("domain"),
                "category": semantic[
                    "classification"
                ].get("category"),
                "confidence": semantic.get(
                    "confidence",
                    "medium"
                ),
                "evidence": {
                    "match": (
                        "service_name"
                        if name_match
                        else "port"
                    ),
                    "source": semantic.get(
                        "source"
                    )
                }
            }

        return None


    def _build_evidence(
        self,
        communication
    ):

        return {
            "context": communication.get(
                "context"
            ),
            "source": communication.get(
                "source",
                {}
            ).get(
                "reference"
            ),
            "destination": communication.get(
                "destination",
                {}
            ).get(
                "reference"
            ),
            "services": communication.get(
                "services",
                []
            )
        }


    def _deduplicate(self, items):

        result = []
        seen = set()

        for item in items:

            key = (
                item.get("service"),
                item.get("domain"),
                item.get("category")
            )

            if key in seen:
                continue

            seen.add(key)
            result.append(item)

        return result