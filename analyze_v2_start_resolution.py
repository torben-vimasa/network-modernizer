from api.digital_twin import DigitalTwin


TESTS = [
    (
        "TPS Logging baseline",
        "172.27.210.20"
    ),
    (
        "BDK Mgmt Oracle backup lower-range sample",
        "10.185.250.81"
    ),
    (
        "BDK Mgmt DWDM Kerberos to AbaneExtDC1",
        "10.26.0.46"
    ),
]


def main():

    twin = DigitalTwin()

    for name, source in TESTS:

        print()
        print("=" * 100)
        print(name)
        print("SOURCE:", source)
        print("=" * 100)

        resolution = (
            twin.endpoint.resolve(
                source
            )
        )

        print()
        print("ENDPOINT RESOLUTION")
        print(resolution)

        attachments = (
            twin.flow_trace_engine._source_attachments(
                resolution
            )
        )

        print()
        print("SOURCE ATTACHMENTS")

        for index, attachment in enumerate(
            attachments,
            start=1
        ):
            print(
                f"{index}: {attachment}"
            )

        start_points = (
            twin.flow_trace_engine._build_start_points(
                attachments
            )
        )

        print()
        print("START POINTS")

        for index, start in enumerate(
            start_points,
            start=1
        ):
            print(
                f"{index}: {start}"
            )


if __name__ == "__main__":
    main()