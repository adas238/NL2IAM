import json
import re

from generator import generate_policy
from validators.validation_engine import ValidationEngine

def build_detailed_validation_trace(validation_result):
    """
    Build a detailed validation report for the agent trace.

    Shows:
    - Custom Validator score and deductions
    - Parliament findings
    - Cloudsplaining findings
    """

    lines = []

    all_findings = validation_result.get(
        "all_findings",
        []
    )

    # --------------------------------------------------------
    # Separate findings by validator
    # --------------------------------------------------------

    custom_findings = []
    parliament_findings = []
    cloudsplaining_findings = []

    for finding in all_findings:

        tool = str(
            finding.get("tool", "")
        ).lower().strip()

        if tool in [
            "custom validator",
            "custom_validator",
            "custom"
        ]:
            custom_findings.append(finding)

        elif tool == "parliament":
            parliament_findings.append(finding)

        elif tool == "cloudsplaining":
            cloudsplaining_findings.append(finding)

    # --------------------------------------------------------
    # CUSTOM VALIDATOR
    # --------------------------------------------------------

    custom_score = validation_result[
        "custom_validator"
    ]["score"]

    lines.append(
        "========== CUSTOM VALIDATOR =========="
    )
    lines.append("")
    lines.append(
        f"Score: {custom_score}/100"
    )

    if not custom_findings:

        lines.append(
            "✅ No findings."
        )

    else:

        lines.append(
            f"❌ Findings: {len(custom_findings)}"
        )

        for index, finding in enumerate(
            custom_findings,
            1
        ):

            severity = finding.get(
                "severity",
                "UNKNOWN"
            )

            category = finding.get(
                "category",
                finding.get(
                    "issue",
                    "UNKNOWN"
                )
            )

            message = finding.get(
                "message",
                finding.get(
                    "details",
                    "No description provided."
                )
            )

            deduction = finding.get(
                "deduction",
                finding.get(
                    "penalty",
                    finding.get(
                        "score_deduction",
                        0
                    )
                )
            )

            lines.append("")
            lines.append(
                f"{index}. [{severity}] {category}"
            )
            lines.append(
                f"   Finding: {message}"
            )

            if deduction:
                lines.append(
                    f"   Marks deducted: -{deduction}"
                )
            else:
                lines.append(
                    "   Marks deducted: Not specified"
                )

    # --------------------------------------------------------
    # PARLIAMENT
    # --------------------------------------------------------

    lines.append("")
    lines.append(
        "========== PARLIAMENT =========="
    )
    lines.append("")

    if not parliament_findings:

        lines.append(
            "✅ No findings."
        )

    else:

        lines.append(
            f"❌ Findings: {len(parliament_findings)}"
        )

        for index, finding in enumerate(
            parliament_findings,
            1
        ):

            severity = finding.get(
                "severity",
                "UNKNOWN"
            )

            category = finding.get(
                "category",
                finding.get(
                    "issue",
                    "UNKNOWN"
                )
            )

            message = finding.get(
                "message",
                finding.get(
                    "details",
                    finding.get(
                        "error",
                        "No description provided."
                    )
                )
            )

            lines.append("")
            lines.append(
                f"{index}. [{severity}] {category}"
            )
            lines.append(
                f"   Finding: {message}"
            )

    # --------------------------------------------------------
    # CLOUDSPLAINING
    # --------------------------------------------------------

    lines.append("")
    lines.append(
        "========== CLOUDSPLAINING =========="
    )
    lines.append("")

    if not cloudsplaining_findings:

        lines.append(
            "✅ No findings."
        )

    else:

        lines.append(
            f"⚠️ Findings: {len(cloudsplaining_findings)}"
        )

        for index, finding in enumerate(
            cloudsplaining_findings,
            1
        ):

            severity = finding.get(
                "severity",
                "UNKNOWN"
            )

            category = finding.get(
                "category",
                finding.get(
                    "issue",
                    "UNKNOWN"
                )
            )

            message = finding.get(
                "message",
                finding.get(
                    "details",
                    "No description provided."
                )
            )

            lines.append("")
            lines.append(
                f"{index}. [{severity}] {category}"
            )
            lines.append(
                f"   Finding: {message}"
            )

    return "\n".join(lines)

# ============================================================
# ORIGINAL INTENT GUARD
# ============================================================

def enforce_original_intent(
    policy,
    intent
):
    """
    Prevent the LLM correction step from inventing
    permissions that were not present in the original
    interpreted intent.

    If the original intent contains a concrete list of
    allowed actions, only those actions are permitted.

    If the original intent itself contains a wildcard such
    as s3:* or *, the guard does NOT guess which specific
    permissions the user intended.
    """

    corrected_policy = json.loads(
        json.dumps(policy)
    )

    changes = []

    allowed_actions = getattr(
        intent,
        "allowed_actions",
        []
    )

    forbidden_actions = getattr(
        intent,
        "forbidden_actions",
        []
    )

    # --------------------------------------------------------
    # Normalize intent actions
    # --------------------------------------------------------

    if isinstance(allowed_actions, str):
        allowed_actions = [allowed_actions]

    if isinstance(forbidden_actions, str):
        forbidden_actions = [forbidden_actions]

    allowed_actions = {
        str(action).strip()
        for action in allowed_actions
        if str(action).strip()
    }

    forbidden_actions = {
        str(action).strip()
        for action in forbidden_actions
        if str(action).strip()
    }

    # --------------------------------------------------------
    # If the original intent itself contains a wildcard,
    # do NOT invent a narrower permission set.
    #
    # Example:
    #   User explicitly asks for s3:*.
    #
    # We cannot safely decide whether that means:
    #   GetObject only
    #   GetObject + PutObject
    #   Full bucket administration
    #   etc.
    # --------------------------------------------------------

    intent_has_wildcard = any(
        action == "*"
        or action.endswith(":*")
        for action in allowed_actions
    )

    if intent_has_wildcard:
        return corrected_policy, changes

    # --------------------------------------------------------
    # Process policy statements
    # --------------------------------------------------------

    statements = corrected_policy.get(
        "Statement",
        []
    )

    if isinstance(statements, dict):
        statements = [statements]

    cleaned_statements = []

    for statement in statements:

        # ----------------------------------------------------
        # Only inspect Allow statements.
        #
        # Explicit Deny statements are not grants and should
        # not be removed just because their action is not in
        # allowed_actions.
        # ----------------------------------------------------

        effect = str(
            statement.get(
                "Effect",
                "Allow"
            )
        ).lower()

        if effect != "allow":
            cleaned_statements.append(statement)
            continue

        actions = statement.get(
            "Action",
            []
        )

        if isinstance(actions, str):
            actions = [actions]

        if not isinstance(actions, list):
            cleaned_statements.append(statement)
            continue

        remaining_actions = []

        for action in actions:

            action = str(action).strip()

            # ------------------------------------------------
            # Explicitly forbidden action
            # ------------------------------------------------

            if action in forbidden_actions:

                changes.append(
                    f"Removed forbidden action "
                    f"'{action}' from the corrected policy."
                )

                continue

            # ------------------------------------------------
            # Concrete original intent
            # ------------------------------------------------

            if action in allowed_actions:

                remaining_actions.append(action)
                continue

            # ------------------------------------------------
            # Wildcard generated by the LLM
            #
            # If original intent is concrete, replace a
            # generated wildcard with the exact requested
            # actions rather than allowing the LLM to invent
            # permissions.
            # ------------------------------------------------

            if action == "*" or action.endswith(":*"):

                if allowed_actions:

                    replacement_actions = sorted(
                        allowed_actions
                    )

                    remaining_actions.extend(
                        replacement_actions
                    )

                    changes.append(
                        f"Replaced broad action '{action}' "
                        f"with the exact actions supported by "
                        f"the original intent: "
                        f"{', '.join(replacement_actions)}."
                    )

                continue

            # ------------------------------------------------
            # Any other action was not part of the original
            # interpreted intent.
            # ------------------------------------------------

            changes.append(
                f"Removed unrequested action "
                f"'{action}' introduced during LLM correction."
            )

        # ----------------------------------------------------
        # Remove duplicate actions while preserving order.
        # ----------------------------------------------------

        unique_actions = []

        for action in remaining_actions:

            if action not in unique_actions:
                unique_actions.append(action)

        # ----------------------------------------------------
        # If nothing remains, remove the Allow statement.
        # ----------------------------------------------------

        if not unique_actions:
            continue

        # ----------------------------------------------------
        # Restore original Action format.
        # ----------------------------------------------------

        if len(unique_actions) == 1:

            statement["Action"] = (
                unique_actions[0]
            )

        else:

            statement["Action"] = (
                unique_actions
            )

        cleaned_statements.append(
            statement
        )

    corrected_policy["Statement"] = (
        cleaned_statements
    )

    return corrected_policy, changes

# ============================================================
# MAIN AGENT
# ============================================================

def run_agent(user_request, provider="ollama", max_attempts=3):

    trace = []

    # --------------------------------------------------------
    # STEP 1: REQUEST RECEIVED
    # --------------------------------------------------------

    trace.append({
        "step": "REQUEST_RECEIVED",
        "message": (
            "Natural-language access requirement received."
        )
    })


    # --------------------------------------------------------
    # STEP 2: INITIAL POLICY GENERATION
    # --------------------------------------------------------

    trace.append({
        "step": "GENERATING_POLICY",
        "message": (
            f"Generating IAM policy using {provider}."
        )
    })

    intent, policy = generate_policy(
        user_request,
        provider=provider
    )

    trace.append({
        "step": "POLICY_GENERATED",
        "message": (
            "Initial IAM policy generated."
        )
    })


    # --------------------------------------------------------
    # VALIDATION / SELF-CORRECTION LOOP
    # --------------------------------------------------------

    for attempt in range(1, max_attempts + 1):

        # ----------------------------------------------------
        # VALIDATION
        # ----------------------------------------------------

        trace.append({
            "step": "VALIDATING",
            "message": (
                f"Validation attempt {attempt}/{max_attempts}."
            )
        })

        validation_engine = ValidationEngine(
            intent,
            policy
        )

        validation_result = validation_engine.validate()


        # ----------------------------------------------------
        # DETAILED VALIDATION SUMMARY
        # ----------------------------------------------------

        custom_score = validation_result[
            "custom_validator"
        ]["score"]

        total_findings = validation_result[
            "summary"
        ]["total_findings"]

        detailed_trace = (
            build_detailed_validation_trace(
                validation_result
            )
        )

        trace.append({
            "step": "VALIDATION_COMPLETE",
            "message": (
                f"Validation attempt {attempt} completed.\n\n"
                f"{detailed_trace}\n\n"
                f"Total findings across all validators: "
                f"{total_findings}."
            )
        })


        # ----------------------------------------------------
        # SUCCESS
        # ----------------------------------------------------

        if validation_result["passed"]:

            trace.append({
                "step": "PASSED",
                "message": (
                    "Policy passed all validation checks."
                )
            })

            return {
                "intent": intent,
                "policy": policy,
                "validation": validation_result,
                "attempts": attempt,
                "trace": trace
            }


        # ----------------------------------------------------
        # FINDINGS DETECTED
        # ----------------------------------------------------

        trace.append({
            "step": "VIOLATIONS_FOUND",
            "message": (
                f"{total_findings} security finding(s) "
                f"detected across the validation tools."
            )
        })


        # ----------------------------------------------------
        # MAXIMUM ATTEMPTS REACHED
        # ----------------------------------------------------

        if attempt == max_attempts:

            trace.append({
                "step": "FAILED",
                "message": (
                    "Maximum correction attempts reached. "
                    "Policy could not be automatically corrected."
                )
            })

            return {
                "intent": intent,
                "policy": policy,
                "validation": validation_result,
                "attempts": attempt,
                "trace": trace
            }


        # ----------------------------------------------------
        # SELF-CORRECTION
        # ----------------------------------------------------

        trace.append({
            "step": "SELF_CORRECTION",
            "message": (
                f"Analyzing validation findings for "
                f"automatic policy correction."
            )
        })


        # ----------------------------------------------------
        # DETERMINISTIC CORRECTION
        #
        # We apply ALL deterministic corrections in the
        # same cycle before asking the LLM for help.
        # ----------------------------------------------------

        corrected_policy, deterministic_changes = (
            apply_deterministic_corrections(
                policy,
                validation_result
            )
        )


        # ----------------------------------------------------
        # APPLY DETERMINISTIC CORRECTIONS
        # ----------------------------------------------------

        if deterministic_changes:

            policy = corrected_policy

            correction_lines = []

            for index, change in enumerate(
                deterministic_changes,
                1
            ):

                correction_lines.append(
                    f"{index}. {change}"
                )

            trace.append({
                "step": "DETERMINISTIC_CORRECTION",
                "message": (
                    "The following corrections were applied:\n\n"
                    + "\n".join(correction_lines)
                )
            })

            trace.append({
                "step": "POLICY_REGENERATED",
                "message": (
                    f"Policy corrected automatically after "
                    f"correction attempt {attempt}.\n"
                    f"Original access intent preserved."
                )
            })

            continue


        # ----------------------------------------------------
        # LLM CORRECTION
        #
        # Only used when no deterministic correction
        # is available.
        # ----------------------------------------------------

        correction_prompt = build_correction_prompt(
            user_request,
            intent,
            policy,
            validation_result
        )

        _, corrected_policy = generate_policy(
            correction_prompt,
            provider=provider
        )

        # ----------------------------------------------------
        # INTENT GUARD
        #
        # The LLM is allowed to correct the policy, but it is
        # NOT allowed to introduce permissions outside the
        # original interpreted intent.
        # ----------------------------------------------------

        guarded_policy, intent_changes = (
            enforce_original_intent(
                corrected_policy,
                intent
            )
        )

        # ----------------------------------------------------
        # Apply Intent Guard corrections
        # ----------------------------------------------------

        policy = guarded_policy

        if intent_changes:

            guard_lines = []

            for index, change in enumerate(
                intent_changes,
                1
            ):

                guard_lines.append(
                    f"{index}. {change}"
                )

            trace.append({
                "step": "INTENT_GUARD",
                "message": (
                    "The LLM correction was checked "
                    "against the original interpreted intent.\n\n"
                    + "\n".join(guard_lines)
                )
            })

        else:

            trace.append({
                "step": "INTENT_GUARD",
                "message": (
                    "LLM correction passed the original "
                    "intent check. No unrequested permissions "
                    "were introduced."
                )
            })

        trace.append({
            "step": "POLICY_REGENERATED",
            "message": (
                f"Policy regenerated using {provider} after "
                f"correction attempt {attempt}.\n"
                f"Original access intent preserved."
            )
        })


    # --------------------------------------------------------
    # FALLBACK
    # --------------------------------------------------------

    return {
        "intent": intent,
        "policy": policy,
        "validation": validation_result,
        "attempts": max_attempts,
        "trace": trace
    }


# ============================================================
# DETERMINISTIC CORRECTION ENGINE
# ============================================================

def apply_deterministic_corrections(
    policy,
    validation_result
):
    """
    Apply deterministic corrections that can be performed
    safely without relying on the LLM.

    Currently handles:

    1. Parliament UNKNOWN_ACTION
    2. Parliament INVALID_SID
    3. S3 RESOURCE_MISMATCH
    4. S3 bucket/object statement separation
    """

    corrected_policy = json.loads(
        json.dumps(policy)
    )

    changes = []

    findings = validation_result.get(
        "all_findings",
        []
    )


    # ========================================================
    # PART 1: FIX INVALID SID VALUES
    # ========================================================

    # ADD THIS
    # Correct duplicate Sid values
    used_sids = set()

    for statement in corrected_policy.get("Statement", []):

        if "Sid" not in statement:
            continue

        sid = statement["Sid"]

        if not isinstance(sid, str):
            continue

        if sid not in used_sids:

            used_sids.add(sid)
            continue

        original_sid = sid
        counter = 2

        new_sid = f"{original_sid}{counter}"

        while new_sid in used_sids:
            counter += 1
            new_sid = f"{original_sid}{counter}"

        statement["Sid"] = new_sid
        used_sids.add(new_sid)

        changes.append(
            f"Corrected duplicate Sid '{original_sid}' to '{new_sid}'."
        )


    # ========================================================
    # PART 2: FIND INVALID IAM ACTIONS
    # ========================================================

    invalid_actions = set()

    for finding in findings:

        category = str(
            finding.get(
                "category",
                finding.get("issue", "")
            )
        ).upper()

        if category != "UNKNOWN_ACTION":
            continue


        # ----------------------------------------------------
        # Search every useful finding field.
        #
        # Parliament messages can differ in formatting.
        # ----------------------------------------------------

        searchable_text = " ".join(
            str(finding.get(field, ""))
            for field in [
                "message",
                "issue",
                "details",
                "error",
                "description"
            ]
        )


        # ----------------------------------------------------
        # Match normal IAM action format:
        #
        # s3:DeleteBucketAcl
        # ec2:Something
        # iam:Something
        # ----------------------------------------------------

        matches = re.findall(
            r"\b[a-zA-Z0-9-]+:[a-zA-Z0-9*]+\b",
            searchable_text
        )


        for action in matches:

            if ":" in action:
                invalid_actions.add(action)


    # ========================================================
    # PART 3: REMOVE ALL INVALID ACTIONS
    # ========================================================

    if invalid_actions:

        statements = corrected_policy.get(
            "Statement",
            []
        )

        if isinstance(statements, dict):
            statements = [statements]

        cleaned_statements = []

        for statement in statements:

            actions = statement.get(
                "Action",
                []
            )

            if isinstance(actions, str):
                actions = [actions]


            remaining_actions = []

            for action in actions:

                if action in invalid_actions:

                    changes.append(
                        f"Removed invalid IAM action "
                        f"'{action}' reported by Parliament."
                    )

                else:

                    remaining_actions.append(action)


            # ------------------------------------------------
            # If no actions remain, remove the statement.
            # ------------------------------------------------

            if not remaining_actions:
                continue


            # ------------------------------------------------
            # Restore original Action format.
            # ------------------------------------------------

            if len(remaining_actions) == 1:

                statement["Action"] = (
                    remaining_actions[0]
                )

            else:

                statement["Action"] = (
                    remaining_actions
                )


            cleaned_statements.append(
                statement
            )


        corrected_policy["Statement"] = (
            cleaned_statements
        )


    # ========================================================
    # PART 4: S3 RESOURCE CORRECTION
    # ========================================================

    s3_object_actions = {
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:GetObjectAcl",
        "s3:PutObjectAcl",
        "s3:GetObjectVersion",
        "s3:DeleteObjectVersion"
    }


    s3_bucket_actions = {
        "s3:ListBucket",
        "s3:ListBucketVersions",
        "s3:GetBucketLocation",
        "s3:GetBucketAcl",
        "s3:PutBucketAcl",
        "s3:GetBucketPolicy",
        "s3:PutBucketPolicy",
        "s3:DeleteBucketPolicy",
        "s3:DeleteBucket"
    }


    statements = corrected_policy.get(
        "Statement",
        []
    )

    if isinstance(statements, dict):
        statements = [statements]


    new_statements = []


    for statement in statements:

        actions = statement.get(
            "Action",
            []
        )

        if isinstance(actions, str):
            actions = [actions]


        # ----------------------------------------------------
        # Only look at recognized S3 actions.
        # ----------------------------------------------------

        bucket_actions = [
            action
            for action in actions
            if action in s3_bucket_actions
        ]

        object_actions = [
            action
            for action in actions
            if action in s3_object_actions
        ]


        # ----------------------------------------------------
        # No recognized S3 actions
        # ----------------------------------------------------

        if not bucket_actions and not object_actions:

            new_statements.append(
                statement
            )

            continue


        # ----------------------------------------------------
        # Find bucket name from Resource.
        # ----------------------------------------------------

        resources = statement.get(
            "Resource",
            []
        )

        if isinstance(resources, str):
            resources = [resources]


        bucket_name = None


        for resource in resources:

            if not isinstance(resource, str):
                continue


            match = re.match(
                r"^arn:aws:s3:::(.+?)(?:/\*)?$",
                resource
            )


            if match:

                bucket_name = match.group(1)
                break


        # ----------------------------------------------------
        # If bucket name cannot be determined,
        # leave the statement alone.
        # ----------------------------------------------------

        if not bucket_name:

            new_statements.append(
                statement
            )

            continue


        bucket_arn = (
            f"arn:aws:s3:::{bucket_name}"
        )

        object_arn = (
            f"arn:aws:s3:::{bucket_name}/*"
        )


        # ====================================================
        # MIXED BUCKET + OBJECT ACTIONS
        # ====================================================

        if bucket_actions and object_actions:

            original_sid = statement.get(
                "Sid",
                "NL2IAMStatement"
            )


            bucket_statement = {
                "Sid": (
                    f"{original_sid}Bucket"
                ),
                "Effect": statement.get(
                    "Effect",
                    "Allow"
                ),
                "Action": (
                    bucket_actions[0]
                    if len(bucket_actions) == 1
                    else bucket_actions
                ),
                "Resource": bucket_arn
            }


            object_statement = {
                "Sid": (
                    f"{original_sid}Objects"
                ),
                "Effect": statement.get(
                    "Effect",
                    "Allow"
                ),
                "Action": (
                    object_actions[0]
                    if len(object_actions) == 1
                    else object_actions
                ),
                "Resource": object_arn
            }


            # ------------------------------------------------
            # Preserve conditions if present.
            # ------------------------------------------------

            if "Condition" in statement:

                bucket_statement["Condition"] = (
                    statement["Condition"]
                )

                object_statement["Condition"] = (
                    statement["Condition"]
                )


            new_statements.append(
                bucket_statement
            )

            new_statements.append(
                object_statement
            )


            changes.append(
                "Split mixed S3 bucket-level and "
                "object-level actions into separate "
                "statements with correct resource ARNs."
            )


            continue


        # ====================================================
        # ONLY BUCKET-LEVEL ACTIONS
        # ====================================================

        if bucket_actions:

            if resources != [bucket_arn]:

                statement["Resource"] = bucket_arn

                changes.append(
                    f"Corrected S3 bucket-level resource "
                    f"to '{bucket_arn}'."
                )


            new_statements.append(
                statement
            )

            continue


        # ====================================================
        # ONLY OBJECT-LEVEL ACTIONS
        # ====================================================

        if object_actions:

            if resources != [object_arn]:

                statement["Resource"] = object_arn

                changes.append(
                    f"Corrected S3 object-level resource "
                    f"to '{object_arn}'."
                )


            new_statements.append(
                statement
            )

            continue


    corrected_policy["Statement"] = (
        new_statements
    )


    return corrected_policy, changes


# ============================================================
# LLM CORRECTION PROMPT
# ============================================================

def build_correction_prompt(
    original_request,
    intent,
    policy,
    validation_result
):

    findings_text = ""


    # --------------------------------------------------------
    # COLLECT ALL FINDINGS
    # --------------------------------------------------------

    for finding in validation_result["all_findings"]:

        tool = finding.get(
            "tool",
            "Unknown Validator"
        )

        severity = finding.get(
            "severity",
            "UNKNOWN"
        )

        category = finding.get(
            "category",
            finding.get(
                "issue",
                "UNKNOWN"
            )
        )

        message = finding.get(
            "message",
            "No description provided."
        )

        findings_text += (
            f"- Tool: {tool}\n"
            f"  Severity: {severity}\n"
            f"  Category: {category}\n"
            f"  Problem: {message}\n"
        )


    # --------------------------------------------------------
    # CORRECTION PROMPT
    # --------------------------------------------------------

    correction_prompt = f"""
You are the POLICY CORRECTION component of NL2IAM.

Your job is NOT to reinterpret the user's request.

Your job is ONLY to correct the current AWS IAM policy
using the security findings provided by the validators.

============================================================
ORIGINAL ACCESS REQUIREMENT
============================================================

{original_request}


============================================================
ORIGINAL INTERPRETED INTENT
============================================================

Team:
{intent.team}

Service:
{intent.service}

Resource:
{intent.resource}

Access Level:
{intent.access_level}

Allowed Actions:
{intent.allowed_actions}

Forbidden Actions:
{intent.forbidden_actions}


============================================================
CURRENT IAM POLICY
============================================================

{json.dumps(policy, indent=2)}


============================================================
SECURITY VALIDATION FINDINGS
============================================================

{findings_text}


============================================================
CRITICAL CORRECTION RULE
============================================================

DO NOT CHANGE THE ORIGINAL ACCESS INTENT.

Only correct the IAM policy.

The ORIGINAL INTERPRETED INTENT is authoritative.

Do not invent, infer, or add new IAM actions.

Every Allow action in the corrected policy must be
supported by intent.allowed_actions.

If an action is not present in intent.allowed_actions,
do not add it.

If a validator reports that an action is invalid,
remove that action.

If the current policy contains a wildcard action
but the original intent contains specific actions,
replace the wildcard only with those exact
actions from intent.allowed_actions.

NEVER replace a broad permission with guessed
permissions such as GetObject or ListBucket unless
those actions are explicitly present in the original
interpreted intent.

If the original intent itself contains a wildcard,
preserve the requested wildcard rather than guessing
which narrower permissions the user meant.

============================================================
AWS IAM RULES
============================================================

- Do not use Action "*" unless explicitly required.
- Do not use unnecessary service wildcards.
- Avoid Resource "*" when a specific resource is possible.
- Do not grant forbidden actions.
- Do not add unrequested permissions.
- Preserve legitimate requested permissions.
- Keep the policy valid AWS IAM JSON.

SID RULE:
- Every Sid value must contain only ASCII letters (A-Z, a-z)
  and numbers (0-9).
- Do not use spaces in Sid values.
- Do not use hyphens, underscores, punctuation, or other
  special characters in Sid values.
- Example of valid Sid: "ReadOnlyFinanceBucket"
- Example of invalid Sid: "Read-only access to finance S3 bucket"

============================================================
S3 RESOURCE RULES
============================================================

Object-level actions:

s3:GetObject
s3:PutObject
s3:DeleteObject

normally use:

arn:aws:s3:::BUCKET_NAME/*


Bucket-level actions:

s3:ListBucket
s3:ListBucketVersions
s3:GetBucketLocation
s3:GetBucketAcl
s3:PutBucketAcl
s3:GetBucketPolicy
s3:PutBucketPolicy
s3:DeleteBucketPolicy
s3:DeleteBucket

normally use:

arn:aws:s3:::BUCKET_NAME

Do not use an object ARN for bucket-level actions.

============================================================
FINAL SELF-CHECK
============================================================

Before returning the policy:

- Remove invalid IAM actions.
- Correct resource mismatches.
- Separate bucket-level and object-level S3 actions.
- Correct invalid Sid values.
- Every Sid must contain only letters and numbers.
- Preserve the original access requirement.
- Avoid unnecessary permissions.
- Ensure the policy is valid IAM JSON.

Return ONLY the corrected JSON object.

The returned object MUST contain:

{{
    "intent": {{
        "team": "...",
        "service": "...",
        "resource": "...",
        "access_level": "...",
        "allowed_actions": [],
        "forbidden_actions": []
    }},
    "policy": {{
        "Version": "2012-10-17",
        "Statement": []
    }}
}}
"""

    return correction_prompt


# ============================================================
# STANDALONE TEST
# ============================================================

if __name__ == "__main__":

    request = """
    The billing team needs the following permissions on the finance S3 bucket:
    s3:GetObject, s3:PutObject, s3:DeleteObject,
    s3:ListBucket, s3:PutBucketPolicy, and s3:PutBucketAcl.
    Do not add any other permissions.
    """

    print("\n==========================================")
    print("        NL2IAM AGENT TEST")
    print("==========================================")

    result = run_agent(
        request,
        provider="gemini",
        max_attempts=3
    )


    print("\n========== AGENT TRACE ==========\n")

    for event in result["trace"]:

        print(
            f"[{event['step']}] "
            f"{event['message']}"
        )


    print("\n========== VALIDATION SUMMARY ==========\n")

    validation = result["validation"]

    print(
        "Overall Passed:",
        validation["passed"]
    )

    print(
        "Custom Validator Score:",
        validation["custom_validator"]["score"]
    )

    print(
        "Custom Validator Findings:",
        validation["summary"]["custom_validator_findings"]
    )

    print(
        "Parliament Findings:",
        validation["summary"]["parliament_findings"]
    )

    print(
        "Cloudsplaining Findings:",
        validation["summary"]["cloudsplaining_findings"]
    )

    print(
        "Total Findings:",
        validation["summary"]["total_findings"]
    )


    print("\n========== FINAL RESULT ==========\n")

    print(
        "Attempts:",
        result["attempts"]
    )

    print(
        "Passed:",
        validation["passed"]
    )

    print("\nPolicy:")

    print(
        json.dumps(
            result["policy"],
            indent=2
        )
    )

    print("\n==================================")
