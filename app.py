import json
import time

import streamlit as st

from agent import run_agent


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="NL2IAM",
    page_icon="🔐",
    layout="wide"
)


# ============================================================
# SESSION STATE
# ============================================================

if "result" not in st.session_state:
    st.session_state.result = None

if "execution_time" not in st.session_state:
    st.session_state.execution_time = None


# ============================================================
# TRACE DISPLAY HELPERS
# ============================================================

TRACE_ICONS = {
    "REQUEST_RECEIVED": "📥",
    "GENERATING_POLICY": "🧠",
    "POLICY_GENERATED": "📄",
    "VALIDATING": "🔍",
    "VALIDATION_COMPLETE": "📊",
    "VIOLATIONS_FOUND": "⚠️",
    "SELF_CORRECTION": "🔄",
    "DETERMINISTIC_CORRECTION": "🛠️",
    "INTENT_GUARD": "🛡️",
    "POLICY_REGENERATED": "♻️",
    "PASSED": "✅",
    "FAILED": "❌"
}


TRACE_NAMES = {
    "REQUEST_RECEIVED": "Request Received",
    "GENERATING_POLICY": "Generating Policy",
    "POLICY_GENERATED": "Policy Generated",
    "VALIDATING": "Validation",
    "VALIDATION_COMPLETE": "Validation Complete",
    "VIOLATIONS_FOUND": "Violations Found",
    "SELF_CORRECTION": "Self-Correction",
    "DETERMINISTIC_CORRECTION": "Deterministic Correction",
    "INTENT_GUARD": "Intent Guard",
    "POLICY_REGENERATED": "Policy Regenerated",
    "PASSED": "Validation Passed",
    "FAILED": "Validation Failed"
}


def display_trace(trace):
    """
    Display the agent execution trace.
    """

    if not trace:
        st.info("No execution trace available.")
        return

    for index, event in enumerate(trace, 1):

        step = event.get(
            "step",
            "UNKNOWN"
        )

        message = event.get(
            "message",
            ""
        )

        icon = TRACE_ICONS.get(
            step,
            "•"
        )

        name = TRACE_NAMES.get(
            step,
            step.replace("_", " ").title()
        )

        with st.expander(
            f"{index}. {icon} {name}",
            expanded=False
        ):

            st.write(message)


# ============================================================
# FINDING HELPERS
# ============================================================

def get_finding_category(finding):
    return finding.get(
        "category",
        finding.get(
            "issue",
            "UNKNOWN"
        )
    )


def get_finding_message(finding):
    return finding.get(
        "message",
        finding.get(
            "details",
            "No description provided."
        )
    )


def get_finding_severity(finding):
    return finding.get(
        "severity",
        "UNKNOWN"
    )


def display_validator_findings(
    validator_name,
    validator_result,
    show_score=False
):
    """
    Display the result and individual findings
    for one validator.
    """

    if validator_result is None:
        st.warning(
            f"No {validator_name} result available."
        )
        return

    passed = validator_result.get(
        "passed",
        False
    )

    findings = validator_result.get(
        "findings",
        []
    )

    if not isinstance(findings, list):
        findings = []

    if passed:
        st.success("PASS")
    else:
        st.error("FAIL")

    if show_score:
        score = validator_result.get(
            "score",
            "N/A"
        )

        st.metric(
            "Least-Privilege Score",
            f"{score}/100"
            if isinstance(score, (int, float))
            else score
        )

    st.write(
        f"**Findings:** {len(findings)}"
    )

    if not findings:

        st.caption(
            f"No {validator_name} findings."
        )

        return

    for index, finding in enumerate(
        findings,
        1
    ):

        severity = get_finding_severity(
            finding
        )

        category = get_finding_category(
            finding
        )

        message = get_finding_message(
            finding
        )

        with st.expander(
            f"{index}. [{severity}] {category}",
            expanded=False
        ):

            st.write(
                f"**Finding:** {message}"
            )

            detail = finding.get(
                "detail",
                finding.get(
                    "details",
                    None
                )
            )

            if detail:
                st.write("**Details:**")

                st.code(
                    str(detail),
                    language="text"
                )

            location = finding.get(
                "location",
                None
            )

            if location:
                st.write("**Location:**")

                st.json(location)


# ============================================================
# COMBINED FINDINGS
# ============================================================

def display_combined_findings(validation):
    """
    Display all findings from all validators.
    """

    all_findings = validation.get(
        "all_findings",
        []
    )

    if not isinstance(all_findings, list):
        all_findings = []

    if not all_findings:

        st.success(
            "No security findings were detected across the validators."
        )

        return

    st.warning(
        f"{len(all_findings)} total finding(s) "
        f"were detected across the validators."
    )

    for index, finding in enumerate(
        all_findings,
        1
    ):

        tool = finding.get(
            "tool",
            "Unknown Validator"
        )

        severity = get_finding_severity(
            finding
        )

        category = get_finding_category(
            finding
        )

        message = get_finding_message(
            finding
        )

        st.write(
            f"**{index}. [{severity}] "
            f"{tool} | {category}**"
        )

        st.write(message)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.title("⚙️ Settings")

    st.subheader("LLM Provider")


    provider = st.radio(
        "Choose provider",
        [
            "ollama",
            "gemini"
        ],
        index=1,
        format_func=lambda value: (
            "Ollama"
            if value == "ollama"
            else "Gemini"
        )
    )


    st.subheader(
        "Maximum correction attempts"
    )

    max_attempts = st.slider(
        "Attempts",
        min_value=1,
        max_value=3,
        value=3
    )

    st.divider()

    st.caption(
        "Ollama runs the LLM locally on your machine. "
        "Gemini uses the cloud API."
    )


# ============================================================
# MAIN HEADER
# ============================================================

st.title("🔐 NL2IAM")

st.subheader(
    "Natural Language to Least-Privilege IAM Policy Generator"
)

st.caption(
    "Generate, validate and automatically correct AWS IAM policies "
    "using multiple independent security validators."
)

st.divider()


# ============================================================
# ACCESS REQUIREMENT
# ============================================================

st.header("📝 Access Requirement")

st.write(
    "Describe what access the user or team needs:"
)

user_request = st.text_area(
    "Natural-language requirement",
    placeholder=(
        "Example: The billing team needs read-only "
        "access to the finance S3 bucket."
    ),
    height=120,
    label_visibility="collapsed"
)

generate_button = st.button(
    "🚀 Generate IAM Policy",
    type="primary",
    use_container_width=True
)


# ============================================================
# RUN AGENT
# ============================================================

if generate_button:

    if not user_request.strip():

        st.warning(
            "Please enter an access requirement first."
        )

    else:

        start_time = time.time()

        with st.spinner(
            "NL2IAM agent is generating, validating and correcting the policy..."
        ):

            result = run_agent(
                user_request,
                provider=provider,
                max_attempts=max_attempts
            )

        end_time = time.time()

        st.session_state.result = result

        st.session_state.execution_time = (
            end_time - start_time
        )

        st.rerun()


# ============================================================
# RESULTS
# ============================================================

result = st.session_state.result


if result is None:

    st.info(
        "Enter an access requirement above and click "
        "**Generate IAM Policy** to start the NL2IAM agent."
    )

else:

    validation = result.get(
        "validation",
        {}
    )

    intent = result.get(
        "intent",
        None
    )

    policy = result.get(
        "policy",
        {}
    )

    attempts = result.get(
        "attempts",
        0
    )

    execution_time = (
        st.session_state.execution_time
    )


    # ========================================================
    # EXECUTION SUMMARY
    # ========================================================

    st.header("📊 Execution Summary")

    custom_validator = validation.get(
        "custom_validator",
        {}
    )

    score = custom_validator.get(
        "score",
        "N/A"
    )

    passed = validation.get(
        "passed",
        False
    )

    summary = validation.get(
        "summary",
        {}
    )

    total_findings = summary.get(
        "total_findings",
        len(
            validation.get(
                "all_findings",
                []
            )
        )
    )

    col1, col2, col3, col4 = st.columns(4)

    with col1:

        st.metric(
            "Least-Privilege Score",
            f"{score}/100"
            if isinstance(score, (int, float))
            else score
        )

    with col2:

        st.metric(
            "Attempts",
            attempts
        )

    with col3:

        st.metric(
            "Overall Status",
            "PASS"
            if passed
            else "FAILED"
        )

    with col4:

        if execution_time is not None:

            st.metric(
                "Execution Time",
                f"{execution_time:.2f}s"
            )


    if passed:

        st.success(
            "The generated IAM policy passed all validation checks."
        )

    else:

        st.error(
            "The policy did not pass all validation checks "
            "within the configured correction attempts."
        )


    # ========================================================
    # INTERPRETED ACCESS INTENT
    # ========================================================

    st.header("🧩 Interpreted Access Intent")

    if intent is not None:

        intent_col1, intent_col2 = st.columns(2)

        with intent_col1:

            st.write(
                f"**Team:** {getattr(intent, 'team', 'N/A')}"
            )

            st.write(
                f"**Service:** {getattr(intent, 'service', 'N/A')}"
            )

            st.write(
                f"**Resource:** {getattr(intent, 'resource', 'N/A')}"
            )

            st.write(
                f"**Access Level:** "
                f"{getattr(intent, 'access_level', 'N/A')}"
            )

        with intent_col2:

            st.write("**Allowed Actions:**")

            allowed_actions = getattr(
                intent,
                "allowed_actions",
                []
            )

            if isinstance(
                allowed_actions,
                str
            ):
                allowed_actions = [
                    allowed_actions
                ]

            if allowed_actions:

                for action in allowed_actions:

                    st.code(
                        action,
                        language="text"
                    )

            else:

                st.caption(
                    "None specified."
                )

            st.write("**Forbidden Actions:**")

            forbidden_actions = getattr(
                intent,
                "forbidden_actions",
                []
            )

            if isinstance(
                forbidden_actions,
                str
            ):
                forbidden_actions = [
                    forbidden_actions
                ]

            if forbidden_actions:

                for action in forbidden_actions:

                    st.code(
                        action,
                        language="text"
                    )

            else:

                st.caption(
                    "None specified."
                )


    # ========================================================
    # FINAL IAM POLICY
    # ========================================================

    st.header("📜 Final IAM Policy")

    st.code(
        json.dumps(
            policy,
            indent=2
        ),
        language="json"
    )


    # ========================================================
    # MULTI-VALIDATOR SECURITY ANALYSIS
    # ========================================================

    st.header(
        "🛡️ Multi-Validator Security Analysis"
    )

    st.caption(
        "The generated policy is independently checked by "
        "three validation mechanisms."
    )


    # ========================================================
    # CUSTOM VALIDATOR
    # ========================================================

    st.subheader(
        "🔍 Custom Validator"
    )

    display_validator_findings(
        "Custom Validator",
        validation.get(
            "custom_validator",
            {}
        ),
        show_score=True
    )


    # ========================================================
    # PARLIAMENT
    # ========================================================

    st.subheader(
        "🏛️ Parliament"
    )

    display_validator_findings(
        "Parliament",
        validation.get(
            "parliament",
            {}
        )
    )


    # ========================================================
    # CLOUDSPLAINING
    # ========================================================

    st.subheader(
        "☁️ Cloudsplaining"
    )

    display_validator_findings(
        "Cloudsplaining",
        validation.get(
            "cloudsplaining",
            {}
        )
    )


    # ========================================================
    # COMBINED FINDINGS
    # ========================================================

    st.header(
        "📋 Combined Security Findings"
    )

    display_combined_findings(
        validation
    )


    # ========================================================
    # AGENT EXECUTION TRACE
    # ========================================================

    st.header(
        "🤖 Agent Execution Trace"
    )

    st.caption(
        "Execution timeline of the self-correction agent."
    )

    display_trace(
        result.get(
            "trace",
            []
        )
    )


    # ========================================================
    # RUN SUMMARY
    # ========================================================

    st.header(
        "📌 Run Summary"
    )

    st.write(
        f"**Provider:** {provider}"
    )

    st.write(
        f"**Maximum correction attempts configured:** "
        f"{max_attempts}"
    )

    st.write(
        f"**Attempts used:** {attempts}"
    )

    st.write(
        f"**Total validator findings:** {total_findings}"
    )

    st.write(
        f"**Overall result:** "
        f"{'PASS' if passed else 'FAILED'}"
    )


    # ========================================================
    # RAW RESULT
    # ========================================================

    with st.expander(
        "🔧 Raw Agent Result"
    ):

        st.json(result)
