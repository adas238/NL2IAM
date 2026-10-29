from validator import IAMValidator
from validators.parliament_validator import ParliamentValidator
from validators.cloudsplaining_validator import CloudsplainingValidator


class ValidationEngine:

    def __init__(self, intent, policy):
        self.intent = intent
        self.policy = policy

    def validate(self):

        # --------------------------------------------------
        # 1. Custom NL2IAM Validator
        # --------------------------------------------------

        custom_validator = IAMValidator(
            self.intent,
            self.policy
        )

        custom_result = custom_validator.validate()

        # --------------------------------------------------
        # 2. Parliament
        # --------------------------------------------------

        parliament_validator = ParliamentValidator(
            self.policy
        )

        parliament_result = parliament_validator.validate()

        # --------------------------------------------------
        # 3. Cloudsplaining
        # --------------------------------------------------

        cloudsplaining_validator = CloudsplainingValidator(
            self.policy
        )

        cloudsplaining_result = cloudsplaining_validator.validate()

        # --------------------------------------------------
        # Aggregate all findings
        # --------------------------------------------------

        all_findings = []

        for finding in custom_result["findings"]:
            finding_copy = dict(finding)
            finding_copy["tool"] = "Custom Validator"
            all_findings.append(finding_copy)

        for finding in parliament_result["findings"]:
            finding_copy = dict(finding)
            finding_copy["tool"] = "Parliament"
            all_findings.append(finding_copy)

        for finding in cloudsplaining_result["findings"]:
            finding_copy = dict(finding)
            finding_copy["tool"] = "Cloudsplaining"
            all_findings.append(finding_copy)

        # --------------------------------------------------
        # Overall status
        # --------------------------------------------------

        overall_passed = (
            custom_result["passed"]
            and parliament_result["passed"]
            and cloudsplaining_result["passed"]
        )

        return {
            "passed": overall_passed,

            "custom_validator": custom_result,

            "parliament": parliament_result,

            "cloudsplaining": cloudsplaining_result,

            "all_findings": all_findings,

            "summary": {
                "custom_validator_findings": len(
                    custom_result["findings"]
                ),
                "parliament_findings": len(
                    parliament_result["findings"]
                ),
                "cloudsplaining_findings": len(
                    cloudsplaining_result["findings"]
                ),
                "total_findings": len(all_findings)
            }
        }