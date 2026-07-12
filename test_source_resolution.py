from api.digital_twin import DigitalTwin


def main():

    dt = DigitalTwin()

    test_ips = [
        "172.27.210.20",
        "172.21.2.62",
    ]

    for source_ip in test_ips:

        print()
        print(source_ip)
        print("=" * 60)

        result = dt.trace.resolver.resolve_source(source_ip)

        print(result)


if __name__ == "__main__":
    main()