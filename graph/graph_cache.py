import hashlib
import json
import pickle
import time
from pathlib import Path


class GraphCache:

    CACHE_VERSION = 1

    def __init__(
        self,
        builder,
        cache_dir=Path("output/cache")
    ):
        self.builder = builder
        self.cache_dir = Path(cache_dir)

        self.cache_file = (
            self.cache_dir
            / "knowledge_graph.pkl"
        )

        self.metadata_file = (
            self.cache_dir
            / "knowledge_graph.meta.json"
        )


    def load_or_build(self):

        start = time.perf_counter()

        fingerprint = (
            self._build_fingerprint()
        )

        if self._cache_is_valid(
            fingerprint
        ):

            try:

                with open(
                    self.cache_file,
                    "rb"
                ) as handle:

                    graph = pickle.load(
                        handle
                    )

                #
                # Rebuild runtime indexes to be
                # defensive across serialized
                # graph instances.
                #
                if hasattr(
                    graph,
                    "rebuild_indexes"
                ):
                    graph.rebuild_indexes()

                elapsed = (
                    time.perf_counter()
                    - start
                )

                print(
                    "Knowledge Graph cache HIT "
                    f"({elapsed:.3f}s)"
                )

                return graph

            except Exception as exc:

                print(
                    "Knowledge Graph cache load "
                    f"failed: {exc}"
                )

        print(
            "Knowledge Graph cache MISS "
            "- rebuilding"
        )

        graph = (
            self.builder
            .build_from_vrf_inventory()
        )

        self._write_cache(
            graph,
            fingerprint
        )

        elapsed = (
            time.perf_counter()
            - start
        )

        print(
            "Knowledge Graph cache updated "
            f"({elapsed:.3f}s)"
        )

        return graph


    def invalidate(self):

        for file in [
            self.cache_file,
            self.metadata_file
        ]:

            try:
                file.unlink()
            except FileNotFoundError:
                pass


    def _cache_is_valid(
        self,
        fingerprint
    ):

        if not self.cache_file.exists():
            return False

        if not self.metadata_file.exists():
            return False

        try:

            with open(
                self.metadata_file,
                "r",
                encoding="utf-8"
            ) as handle:

                metadata = json.load(
                    handle
                )

        except Exception:
            return False

        if (
            metadata.get(
                "cache_version"
            )
            != self.CACHE_VERSION
        ):
            return False

        return (
            metadata.get(
                "fingerprint"
            )
            == fingerprint
        )


    def _write_cache(
        self,
        graph,
        fingerprint
    ):

        self.cache_dir.mkdir(
            parents=True,
            exist_ok=True
        )

        temp_cache = (
            self.cache_file
            .with_suffix(".tmp")
        )

        temp_metadata = (
            self.metadata_file
            .with_suffix(".tmp")
        )

        with open(
            temp_cache,
            "wb"
        ) as handle:

            pickle.dump(
                graph,
                handle,
                protocol=pickle.HIGHEST_PROTOCOL
            )

        metadata = {
            "cache_version": (
                self.CACHE_VERSION
            ),
            "fingerprint": (
                fingerprint
            )
        }

        with open(
            temp_metadata,
            "w",
            encoding="utf-8"
        ) as handle:

            json.dump(
                metadata,
                handle,
                indent=2
            )

        temp_cache.replace(
            self.cache_file
        )

        temp_metadata.replace(
            self.metadata_file
        )


    def _build_fingerprint(self):

        digest = hashlib.sha256()

        files = (
            self._input_files()
        )

        for file in files:

            relative = (
                file.as_posix()
            )

            digest.update(
                relative.encode(
                    "utf-8"
                )
            )

            try:

                stat = file.stat()

            except FileNotFoundError:
                continue

            digest.update(
                str(
                    stat.st_size
                ).encode(
                    "ascii"
                )
            )

            digest.update(
                str(
                    stat.st_mtime_ns
                ).encode(
                    "ascii"
                )
            )

        return digest.hexdigest()


    def _input_files(self):

        files = []

        #
        # Explicit GraphBuilder inputs.
        #
        explicit_files = [
            Path("output/vrf_inventory.json"),
            Path("output/vrf_asa_topology.json"),
            Path("output/network_objects.json"),
            Path("output/object_groups.json"),
            Path("output/rules.json"),
            Path("output/firewall_interfaces.json"),
            Path("output/access_groups.json"),
            Path("output/router_interfaces.json"),
            Path("output/hsrp_status.json"),
            Path(
                "output/"
                "firewall_bgp_neighbors.json"
            ),
            Path(
                "knowledge/"
                "applications.json"
            )
        ]

        for file in explicit_files:

            if file.exists():
                files.append(file)

        #
        # Raw router inventory consumed by
        # GraphBuilder._add_router_inventory().
        #
        router_dir = Path(
            "data/router_raw"
        )

        if router_dir.exists():

            files.extend(
                file
                for file
                in router_dir.rglob(
                    "*section interface*.txt"
                )
                if file.is_file()
            )

        #
        # Inventory() may resolve firewall /
        # context ownership from repository
        # inventory data. Include inventory
        # source files defensively.
        #
        inventory_dirs = [
            Path("inventory"),
            Path("data/inventory")
        ]

        for directory in inventory_dirs:

            if not directory.exists():
                continue

            files.extend(
                file
                for file
                in directory.rglob("*")
                if (
                    file.is_file()
                    and file.suffix.lower()
                    in {
                        ".json",
                        ".yaml",
                        ".yml",
                        ".csv",
                        ".txt"
                    }
                )
            )

        #
        # Changes to graph construction code
        # must invalidate persisted graphs.
        #
        code_files = [
            Path(
                "builders/"
                "graph_builder.py"
            ),
            Path(
                "graph/"
                "graph.py"
            ),
            Path(
                "graph/"
                "nodes.py"
            ),
            Path(
                "graph/"
                "relationships.py"
            )
        ]

        for file in code_files:

            if file.exists():
                files.append(file)

        #
        # Stable deterministic order.
        #
        unique = {
            file.resolve()
            for file in files
        }

        return sorted(
            unique,
            key=lambda item: (
                item.as_posix()
            )
        )
