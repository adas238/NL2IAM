import json
import parliament


class ParliamentValidator:

    # Parliament itself does not assign our project's
    # HIGH / MEDIUM / LOW severity levels.
    # We map common Parliament findings to useful severity levels.
    SEVERITY_MAP = {
        "RESOURCE_STAR": "HIGH",
        "ACTION_STAR": "CRITICAL",
        "PRIVILEGE_ESCALATION": "CRITICAL",
        "RESOURCE_MISSING": "MEDIUM",
        "UNKNOWN_ACTION": "MEDIUM",
        "UNKNOWN_CONDITION": "MEDIUM",
        "INVALID_ARN": "MEDIUM",
    }

    def __init__(self, policy):
        self.policy = policy

    def validate(self):
        """
        Analyze an IAM policy using Parliament.

        Returns a clean dictionary that can later be consumed
        by the NL2IAM Validation Engine.
        """

        try:
            # Parliament's Python API expects a JSON string.
            policy_string = json.dumps(self.policy)

            # Run Parliament analysis.
            result = parliament.analyze_policy_string(policy_string)

            findings = []

            for finding in result.findings:

                issue = getattr(finding, "issue", "UNKNOWN")
                detail = getattr(finding, "detail", [])
                location = getattr(finding, "location", {})

                # Parliament normally returns detail as a list.
                if isinstance(detail, list):
                    detail_text = ", ".join(str(item) for item in detail)
                else:
                    detail_text = str(detail)

                severity = self.SEVERITY_MAP.get(
                    issue,
                    "MEDIUM"
                )

                findings.append({
                    "severity": severity,
                    "issue": issue,
                    "message": self.create_message(
                        issue,
                        detail
                    ),
                    "detail": detail,
                    "location": location
                })

            passed = len(findings) == 0

            return {
                "tool": "Parliament",
                "passed": passed,
                "findings": findings,
                "error": None
            }

        except Exception as e:

            return {
                "tool": "Parliament",
                "passed": False,
                "findings": [],
                "error": str(e)
            }

    def create_message(self, issue, detail):
        """
        Convert Parliament's issue code into a
        human-readable explanation.
        """

        messages = {

            "RESOURCE_STAR":
                "The policy uses Resource '*' which may grant "
                "access to more resources than necessary.",

            "ACTION_STAR":
                "The policy uses Action '*' which grants "
                "very broad permissions.",

            "PRIVILEGE_ESCALATION":
                "The policy contains a permission that may "
                "allow privilege escalation.",

            "RESOURCE_MISSING":
                "The policy statement is missing a resource.",

            "UNKNOWN_ACTION":
                "The policy contains an unknown or invalid IAM action.",

            "UNKNOWN_CONDITION":
                "The policy contains an unknown or invalid condition.",

            "INVALID_ARN":
                "The policy contains an invalid AWS ARN.",

        }

        if issue in messages:
            message = messages[issue]
        else:
            message = f"Parliament detected the issue: {issue}"

        # Add affected actions when Parliament provides them.
        if detail:
            if isinstance(detail, list):
                if len(detail) <= 5:
                    affected = ", ".join(str(item) for item in detail)
                    message += f" Affected items: {affected}."
                else:
                    message += (
                        f" Parliament identified {len(detail)} "
                        f"affected items."
                    )

        return message