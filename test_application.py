from models.application import Application
from models.application_flow import ApplicationFlow


kms = Application(

    name="KMS",

    business_service="Rail Power",

    owner="Banedanmark",

    criticality="mission-critical",

    max_outage_minutes=10,

    description="Power monitoring"
)

kms.flows.append(

    ApplicationFlow(

        source="172.27.210.20",

        destination="SPNS2_Logpoint_100.72.36.70",

        protocol="object-group",

        service="Windows_Logging",

        description="Operational logging"
    )

)

print()

print("Application")
print("=" * 50)

print(kms)

print()

print("Flows")

for flow in kms.flows:

    print(flow)