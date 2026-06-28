from api.digital_twin import DigitalTwin

dt = DigitalTwin()

packet = dt.application.build_packet("KMS")

print()
print("Application Trace")
print("=" * 50)

print(packet)