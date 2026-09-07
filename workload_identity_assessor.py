import csv
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import msal
import requests


TENANT_ID = os.environ.get("AUTUMN_TENANT_ID")
CLIENT_ID = os.environ.get("AUTUMN_CLIENT_ID")

if not TENANT_ID or not CLIENT_ID:
    print("Missing AUTUMN_TENANT_ID or AUTUMN_CLIENT_ID.")
    sys.exit(1)

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPES = ["Application.Read.All"]
GRAPH = "https://graph.microsoft.com/v1.0"

REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)

ACCEPTED_RISK_FILE = Path("accepted_risks.json")

HIGH_IMPACT_PERMISSIONS = {
    "RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All",
    "Application.ReadWrite.All",
    "Directory.ReadWrite.All",
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
}

BROAD_READ_PERMISSIONS = {
    "Directory.Read.All",
    "Application.Read.All",
    "Group.Read.All",
    "User.Read.All",
}


def parse_graph_date(value):
    if not value:
        return None

    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def days_until(value):
    dt = parse_graph_date(value)

    if not dt:
        return None

    return (dt - datetime.now(timezone.utc)).days


def credential_lifetime(start, end):
    start_dt = parse_graph_date(start)
    end_dt = parse_graph_date(end)

    if not start_dt or not end_dt:
        return None

    return (end_dt - start_dt).days


def add_finding(
    findings,
    severity,
    identity,
    identity_type,
    category,
    finding,
    detail,
    permission=None,
):
    findings.append(
        {
            "severity": severity,
            "identity": identity,
            "identity_type": identity_type,
            "category": category,
            "finding": finding,
            "detail": detail,
            "permission": permission,
            "status": "OPEN",
            "businessJustification": "",
            "technicalOwner": "",
            "compensatingControls": [],
            "nextReviewDate": "",
        }
    )


def load_accepted_risks():
    if not ACCEPTED_RISK_FILE.exists():
        return []

    with open(
        ACCEPTED_RISK_FILE,
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)


def apply_risk_dispositions(findings, accepted_risks):
    for finding in findings:
        for accepted in accepted_risks:
            identity_match = (
                finding["identity"] == accepted.get("identity")
            )

            finding_match = (
                finding["finding"] == accepted.get("finding")
            )

            permission_match = (
                not accepted.get("permission")
                or finding.get("permission") == accepted.get("permission")
            )

            if identity_match and finding_match and permission_match:
                finding["status"] = accepted.get(
                    "disposition",
                    "ACCEPTED",
                )

                finding["businessJustification"] = accepted.get(
                    "businessJustification",
                    "",
                )

                finding["technicalOwner"] = accepted.get(
                    "technicalOwner",
                    "",
                )

                finding["compensatingControls"] = accepted.get(
                    "compensatingControls",
                    [],
                )

                finding["nextReviewDate"] = accepted.get(
                    "nextReviewDate",
                    "",
                )

                break


app = msal.PublicClientApplication(
    client_id=CLIENT_ID,
    authority=AUTHORITY,
)

print()
print("AUTUMN SOLUTIONS")
print("Workload Identity Security Assessment")
print("=" * 62)
print()
print("Authenticating to Microsoft Entra ID...")

token = app.acquire_token_interactive(
    scopes=SCOPES,
)

if "access_token" not in token:
    print("Authentication failed.")
    print(token.get("error"))
    print(token.get("error_description"))
    sys.exit(1)

headers = {
    "Authorization": f"Bearer {token['access_token']}",
}


def graph_get_all(url):
    results = []

    if not url.startswith("http"):
        url = f"{GRAPH}{url}"

    while url:
        response = requests.get(
            url,
            headers=headers,
            timeout=30,
        )

        if not response.ok:
            raise RuntimeError(
                f"Graph request failed: {response.status_code}\n"
                f"{response.text}"
            )

        payload = response.json()

        results.extend(
            payload.get("value", [])
        )

        url = payload.get("@odata.nextLink")

    return results


print("Authentication successful.")
print("Collecting application and service principal data...")
print()

applications = graph_get_all(
    "/applications"
    "?$select=id,appId,displayName,createdDateTime,"
    "passwordCredentials,keyCredentials"
)

service_principals = graph_get_all(
    "/servicePrincipals"
    "?$select=id,appId,displayName,servicePrincipalType,"
    "accountEnabled,appRoles"
)

application_ids = {
    item["appId"]
    for item in applications
    if item.get("appId")
}

local_service_principals = [
    sp
    for sp in service_principals
    if sp.get("appId") in application_ids
]

service_principal_by_id = {
    sp["id"]: sp
    for sp in service_principals
    if sp.get("id")
}

findings = []
permission_inventory = []


# APPLICATION OWNERSHIP AND CREDENTIALS

for application in applications:
    name = application.get(
        "displayName",
        "Unnamed Application",
    )

    object_id = application["id"]

    owners = graph_get_all(
        f"/applications/{object_id}/owners"
        "?$select=id,displayName"
    )

    if len(owners) == 0:
        add_finding(
            findings,
            "MEDIUM",
            name,
            "Application",
            "Ownership",
            "Application has no assigned owner",
            "No owner is assigned to the app registration, "
            "reducing accountability and lifecycle governance.",
        )

    for secret in application.get(
        "passwordCredentials",
        [],
    ):
        expiry_days = days_until(
            secret.get("endDateTime")
        )

        lifetime_days = credential_lifetime(
            secret.get("startDateTime"),
            secret.get("endDateTime"),
        )

        credential_name = (
            secret.get("displayName")
            or "Unnamed client secret"
        )

        if expiry_days is not None and expiry_days < 0:
            add_finding(
                findings,
                "HIGH",
                name,
                "Application",
                "Credential",
                "Expired client secret",
                f"{credential_name} expired "
                f"{abs(expiry_days)} days ago.",
            )

        elif (
            expiry_days is not None
            and expiry_days <= 30
        ):
            add_finding(
                findings,
                "HIGH",
                name,
                "Application",
                "Credential",
                "Client secret expires within 30 days",
                f"{credential_name} expires in "
                f"{expiry_days} days.",
            )

        elif (
            expiry_days is not None
            and expiry_days <= 90
        ):
            add_finding(
                findings,
                "MEDIUM",
                name,
                "Application",
                "Credential",
                "Client secret expires within 90 days",
                f"{credential_name} expires in "
                f"{expiry_days} days.",
            )

        if (
            lifetime_days is not None
            and lifetime_days > 365
        ):
            add_finding(
                findings,
                "MEDIUM",
                name,
                "Application",
                "Credential",
                "Long-lived client secret",
                f"{credential_name} has a configured "
                f"lifetime of {lifetime_days} days.",
            )

    for certificate in application.get(
        "keyCredentials",
        [],
    ):
        expiry_days = days_until(
            certificate.get("endDateTime")
        )

        certificate_name = (
            certificate.get("displayName")
            or certificate.get("type")
            or "Certificate credential"
        )

        if expiry_days is not None and expiry_days < 0:
            add_finding(
                findings,
                "HIGH",
                name,
                "Application",
                "Credential",
                "Expired certificate credential",
                f"{certificate_name} expired "
                f"{abs(expiry_days)} days ago.",
            )

        elif (
            expiry_days is not None
            and expiry_days <= 30
        ):
            add_finding(
                findings,
                "HIGH",
                name,
                "Application",
                "Credential",
                "Certificate expires within 30 days",
                f"{certificate_name} expires in "
                f"{expiry_days} days.",
            )

        elif (
            expiry_days is not None
            and expiry_days <= 90
        ):
            add_finding(
                findings,
                "MEDIUM",
                name,
                "Application",
                "Credential",
                "Certificate expires within 90 days",
                f"{certificate_name} expires in "
                f"{expiry_days} days.",
            )


# SERVICE PRINCIPAL OWNERSHIP AND APP PERMISSIONS

for service_principal in local_service_principals:
    name = service_principal.get(
        "displayName",
        "Unnamed Service Principal",
    )

    object_id = service_principal["id"]

    owners = graph_get_all(
        f"/servicePrincipals/{object_id}/owners"
        "?$select=id,displayName"
    )

    if len(owners) == 0:
        add_finding(
            findings,
            "MEDIUM",
            name,
            "Service Principal",
            "Ownership",
            "Service principal has no assigned owner",
            "No owner is assigned to the enterprise "
            "application service principal.",
        )

    assignments = graph_get_all(
        f"/servicePrincipals/{object_id}/appRoleAssignments"
        "?$select=id,appRoleId,resourceId,resourceDisplayName"
    )

    for assignment in assignments:
        resource_id = assignment.get("resourceId")
        app_role_id = assignment.get("appRoleId")

        resource_name = (
            assignment.get("resourceDisplayName")
            or "Unknown Resource"
        )

        resource_sp = service_principal_by_id.get(
            resource_id,
            {},
        )

        permission_name = None

        for role in resource_sp.get(
            "appRoles",
            [],
        ):
            if role.get("id") == app_role_id:
                permission_name = (
                    role.get("value")
                    or role.get("displayName")
                )
                break

        if not permission_name:
            permission_name = (
                app_role_id
                or "Unknown Permission"
            )

        permission_inventory.append(
            {
                "identity": name,
                "resource": resource_name,
                "permission": permission_name,
            }
        )

        if permission_name in HIGH_IMPACT_PERMISSIONS:
            add_finding(
                findings,
                "HIGH",
                name,
                "Service Principal",
                "Permission",
                "High-impact application permission",
                f"{permission_name} granted against "
                f"{resource_name}.",
                permission=permission_name,
            )

        elif permission_name in BROAD_READ_PERMISSIONS:
            add_finding(
                findings,
                "MEDIUM",
                name,
                "Service Principal",
                "Permission",
                "Broad directory read permission",
                f"{permission_name} granted against "
                f"{resource_name}.",
                permission=permission_name,
            )


# APPLY ACCEPTED-RISK DECISIONS

accepted_risks = load_accepted_risks()

apply_risk_dispositions(
    findings,
    accepted_risks,
)


# SORT AND REPORT

severity_order = {
    "HIGH": 0,
    "MEDIUM": 1,
    "LOW": 2,
}

status_order = {
    "OPEN": 0,
    "ACCEPTED": 1,
}

findings.sort(
    key=lambda item: (
        status_order.get(
            item["status"],
            99,
        ),
        severity_order.get(
            item["severity"],
            99,
        ),
        item["identity"].lower(),
    )
)

open_findings = [
    item
    for item in findings
    if item["status"] == "OPEN"
]

accepted_findings = [
    item
    for item in findings
    if item["status"] == "ACCEPTED"
]

open_high = sum(
    1
    for item in open_findings
    if item["severity"] == "HIGH"
)

open_medium = sum(
    1
    for item in open_findings
    if item["severity"] == "MEDIUM"
)

open_low = sum(
    1
    for item in open_findings
    if item["severity"] == "LOW"
)

timestamp = datetime.now(
    timezone.utc
).isoformat()

report = {
    "assessment":
        "Autumn Solutions Workload Identity Security Assessment",
    "generatedAt": timestamp,
    "applicationsAssessed": len(applications),
    "localServicePrincipalsAssessed":
        len(local_service_principals),
    "totalDetectedFindings": len(findings),
    "openFindingsCount": len(open_findings),
    "acceptedFindingsCount": len(accepted_findings),
    "openSeverityCounts": {
        "high": open_high,
        "medium": open_medium,
        "low": open_low,
    },
    "findings": findings,
    "applicationPermissions":
        permission_inventory,
}

with open(
    REPORT_DIR / "workload_identity_assessment.json",
    "w",
    encoding="utf-8",
) as file:
    json.dump(
        report,
        file,
        indent=2,
    )

with open(
    REPORT_DIR / "workload_identity_findings.csv",
    "w",
    newline="",
    encoding="utf-8",
) as file:
    fieldnames = [
        "status",
        "severity",
        "identity",
        "identity_type",
        "category",
        "finding",
        "permission",
        "detail",
        "businessJustification",
        "technicalOwner",
        "nextReviewDate",
    ]

    writer = csv.DictWriter(
        file,
        fieldnames=fieldnames,
        extrasaction="ignore",
    )

    writer.writeheader()
    writer.writerows(findings)


print("ASSESSMENT SUMMARY")
print("-" * 62)
print(
    f"Applications assessed:              "
    f"{len(applications)}"
)
print(
    f"Local service principals assessed: "
    f"{len(local_service_principals)}"
)
print(
    f"Total detected findings:           "
    f"{len(findings)}"
)
print(
    f"Open findings:                     "
    f"{len(open_findings)}"
)
print(
    f"Accepted findings:                 "
    f"{len(accepted_findings)}"
)
print(
    f"Open High:                         "
    f"{open_high}"
)
print(
    f"Open Medium:                       "
    f"{open_medium}"
)
print(
    f"Open Low:                          "
    f"{open_low}"
)
print()


if open_findings:
    print("OPEN SECURITY FINDINGS")
    print("-" * 62)

    for number, finding in enumerate(
        open_findings,
        start=1,
    ):
        print(
            f"{number}. [{finding['severity']}] "
            f"{finding['identity']} | "
            f"{finding['finding']}"
        )

        print(
            f"   {finding['detail']}"
        )

        print()

else:
    print("OPEN SECURITY FINDINGS")
    print("-" * 62)
    print("No unresolved findings detected.")
    print()


if accepted_findings:
    print("ACCEPTED RISK")
    print("-" * 62)

    for number, finding in enumerate(
        accepted_findings,
        start=1,
    ):
        print(
            f"{number}. [ACCEPTED / "
            f"{finding['severity']}] "
            f"{finding['identity']}"
        )

        print(
            f"   Finding: "
            f"{finding['finding']}"
        )

        if finding.get("permission"):
            print(
                f"   Permission: "
                f"{finding['permission']}"
            )

        print(
            f"   Business justification: "
            f"{finding['businessJustification']}"
        )

        print(
            f"   Technical owner: "
            f"{finding['technicalOwner']}"
        )

        print(
            f"   Next review: "
            f"{finding['nextReviewDate']}"
        )

        print(
            "   Compensating controls:"
        )

        for control in finding[
            "compensatingControls"
        ]:
            print(
                f"      - {control}"
            )

        print()


print("Reports written:")
print(
    "  reports/"
    "workload_identity_assessment.json"
)
print(
    "  reports/"
    "workload_identity_findings.csv"
)
print()
