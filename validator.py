class IAMValidator:

    def __init__(self, intent, policy):

        self.intent = intent
        self.policy = policy

        self.findings = []
        self.score = 100

    def add_finding(
        self,
        severity,
        category,
        message,
        deduction
    ):

        self.findings.append({
            "severity": severity,
            "category": category,
            "message": message,
            "deduction": deduction
        })

        self.score -= deduction

    def is_allow_statement(self, statement):

        effect = statement.get(
            "Effect",
            "Allow"
        )

        return str(effect).lower() == "allow"

    def validate(self):

        self.check_action_wildcards()
        self.check_service_wildcards()
        self.check_resource_wildcards()
        self.check_forbidden_actions()
        self.check_unrequested_actions()

        if self.score < 0:
            self.score = 0

        passed = len(self.findings) == 0

        return {
            "score": self.score,
            "passed": passed,
            "findings": self.findings
        }

    def check_action_wildcards(self):

        for statement in self.policy.get("Statement", []):

            # Only check permissions that are actually granted
            if not self.is_allow_statement(statement):
                continue

            actions = statement.get("Action", [])

            if isinstance(actions, str):
                actions = [actions]

            for action in actions:

                if action == "*":

                    self.add_finding(
                        "CRITICAL",
                        "ACTION_WILDCARD",
                        "Policy grants all AWS actions using Action '*'.",
                        40
                    )

    def check_service_wildcards(self):

        for statement in self.policy.get("Statement", []):

            # Only check permissions that are actually granted
            if not self.is_allow_statement(statement):
                continue

            actions = statement.get("Action", [])

            if isinstance(actions, str):
                actions = [actions]

            for action in actions:

                if action.endswith(":*"):

                    self.add_finding(
                        "HIGH",
                        "SERVICE_WILDCARD",
                        f"Broad service wildcard detected: {action}",
                        30
                    )

    def check_resource_wildcards(self):

        for statement in self.policy.get("Statement", []):

            # Only check permissions that are actually granted
            if not self.is_allow_statement(statement):
                continue

            actions = statement.get("Action", [])
            resources = statement.get("Resource", [])

            if isinstance(actions, str):
                actions = [actions]

            if isinstance(resources, str):
                resources = [resources]

            for action in actions:

                for resource in resources:

                    if resource != "*":
                        continue

                    # Some AWS actions do not support
                    # resource-level permissions and therefore
                    # legitimately require Resource "*".
                    #
                    # For these actions, Resource "*" is valid.
                    if self.action_allows_wildcard_resource(action):
                        continue

                    self.add_finding(
                        "HIGH",
                        "RESOURCE_WILDCARD",
                        "Policy uses Resource '*' instead of a specific resource.",
                        20
                    )

    def action_allows_wildcard_resource(self, action):

        wildcard_resource_actions = {

            # EC2 read-only / describe actions
            "ec2:DescribeInstances",
            "ec2:DescribeInstanceTypes",
            "ec2:DescribeRegions",
            "ec2:DescribeAvailabilityZones",
            "ec2:DescribeImages",
            "ec2:DescribeSnapshots",
            "ec2:DescribeVolumes",
            "ec2:DescribeSecurityGroups",
            "ec2:DescribeSubnets",
            "ec2:DescribeVpcs",
            "ec2:DescribeTags",

        }

        return action.lower() in {
            item.lower()
            for item in wildcard_resource_actions
        }

    def check_forbidden_actions(self):

        forbidden = set(
            action.lower()
            for action in self.intent.forbidden_actions
        )

        for statement in self.policy.get("Statement", []):

            # A Deny statement does not grant the forbidden action.
            if not self.is_allow_statement(statement):
                continue

            actions = statement.get("Action", [])

            if isinstance(actions, str):
                actions = [actions]

            for action in actions:

                if action.lower() in forbidden:

                    self.add_finding(
                        "CRITICAL",
                        "FORBIDDEN_ACTION",
                        f"Policy grants explicitly forbidden action: {action}",
                        35
                    )

    def check_unrequested_actions(self):

        allowed = set(
            action.lower()
            for action in self.intent.allowed_actions
        )

        forbidden = set(
            action.lower()
            for action in self.intent.forbidden_actions
        )

        for statement in self.policy.get("Statement", []):

            # Only Allow statements grant permissions.
            if not self.is_allow_statement(statement):
                continue

            actions = statement.get("Action", [])

            if isinstance(actions, str):
                actions = [actions]

            for action in actions:

                action_lower = action.lower()

                if (
                    action_lower not in allowed
                    and action_lower not in forbidden
                    and action != "*"
                    and not action.endswith(":*")
                ):

                    self.add_finding(
                        "MEDIUM",
                        "UNREQUESTED_ACTION",
                        f"Policy grants action not explicitly requested: {action}",
                        15
                    )
