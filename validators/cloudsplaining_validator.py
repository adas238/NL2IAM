from cloudsplaining.command.scan_policy_file import scan_policy
from cloudsplaining.shared.constants import DEFAULT_EXCLUSIONS_CONFIG


class CloudsplainingValidator:

    SEVERITY_MAP = {
        "PrivilegeEscalation": "CRITICAL",
        "DataExfiltration": "HIGH",
        "ResourceExposure": "HIGH",
        "ServiceWildcard": "HIGH",
        "CredentialsExposure": "CRITICAL",
        "InfrastructureModification": "HIGH",
    }

    DISPLAY_NAMES = {
        "PrivilegeEscalation": "Privilege Escalation",
        "DataExfiltration": "Data Exfiltration",
        "ResourceExposure": "Resource Exposure",
        "ServiceWildcard": "Service Wildcard",
        "CredentialsExposure": "Credentials Exposure",
        "InfrastructureModification": "Infrastructure Modification",
    }

    def __init__(self, policy):
        self.policy = policy

    def validate(self):
        try:
            results = scan_policy(
                self.policy,
                DEFAULT_EXCLUSIONS_CONFIG,
                flag_resource_arn_statements=False,
                flag_conditional_statements=False,
                severity=None,
            )

            findings = []

            for category, category_result in results.items():

                # Cloudsplaining also returns metadata such as
                # ServicesAffected, which is not a finding category.
                if not isinstance(category_result, dict):
                    continue

                category_findings = category_result.get("findings", [])

                if not category_findings:
                    continue

                severity = self.SEVERITY_MAP.get(category, "MEDIUM")
                display_name = self.DISPLAY_NAMES.get(category, category)

                affected_items = []

                for finding in category_findings:

                    if isinstance(finding, dict):
                        actions = finding.get("actions", [])

                        if actions:
                            affected_items.extend(
                                str(action) for action in actions
                            )
                        else:
                            affected_items.append(str(finding))

                    else:
                        affected_items.append(str(finding))

                # Remove duplicates while preserving order
                affected_items = list(dict.fromkeys(affected_items))

                if not affected_items:
                    continue

                # Create ONE finding for the entire category
                findings.append({
                    "severity": severity,
                    "issue": category,
                    "type": category,
                    "message": (
                        f"Cloudsplaining detected {display_name} risk "
                        f"affecting {len(affected_items)} item(s)."
                    ),
                    "actions": affected_items,
                    "count": len(affected_items)
                })

            passed = len(findings) == 0

            return {
                "tool": "Cloudsplaining",
                "passed": passed,
                "findings": findings,
                "error": None
            }

        except Exception as e:
            return {
                "tool": "Cloudsplaining",
                "passed": False,
                "findings": [],
                "error": str(e)
            }