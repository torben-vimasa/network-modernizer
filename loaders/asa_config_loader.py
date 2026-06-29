from pathlib import Path


class ASAConfigLoader:

    def load(self, filename):

        return Path(filename).read_text(
            encoding="utf-8",
            errors="ignore"
        ).splitlines()