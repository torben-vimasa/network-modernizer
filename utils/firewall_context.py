import re


def detect_firewall_context(file_path):

    try:
        with open(
            file_path,
            encoding="utf-8",
            errors="ignore"
        ) as handle:

            for _ in range(10):

                line = handle.readline()

                if not line:
                    break

                line = line.strip()

                #
                # Example:
                #
                # TCCE-CAT2-FW/unit-1-1/master/CAT2-DMZ# show run
                #
                match = re.match(
                    r"^.+/(?P<context>[^/#]+)#\s+show\s+",
                    line
                )

                if match:
                    return match.group("context")

    except OSError:
        pass

    return file_path.stem