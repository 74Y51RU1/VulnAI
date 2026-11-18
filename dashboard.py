
import json
from datetime import datetime

import streamlit as st

from scanner import (
    scan_target,
    clean_scan_output,
    scan_infrastructure,
    validate_scan_ip,
)
from http_checker import check_http
from agent import analyse_finding
from target_validator import validate_target
from security_checks import check_security_headers
from cookie_checks import check_cookie_security
from cors_checks import check_cors
from infrastructure_checks import check_infrastructure_exposure
from public_assessment import assess_public_website
from report_generator import generate_pdf_report
from scan_history import (
    initialize_database,
    save_assessment,
    get_scan_history,
    get_assessment,
)
from scan_comparison import compare_assessments
from web_comparison import compare_web_assessments

st.set_page_config(
    page_title="VulnAI",
    page_icon="🛡️",
    layout="wide",
)

initialize_database()

INFRA_MODE = "Infrastructure Assessment"
LOCAL_WEB_MODE = "Web Assessment"
PUBLIC_WEB_MODE = "Public Website Assessment"



def display_comparison_list(title, items, column_name):
    st.markdown(f"#### {title}")

    if not items:
        st.info("None observed.")
        return

    rows = [{column_name: item} for item in items]

    st.dataframe(
        rows,
        use_container_width=True,
        hide_index=True,
    )


def build_pdf(results):
    return generate_pdf_report(
        target_url=results["target_url"],
        nmap_evidence=results["nmap_evidence"],
        http_evidence=results["http_evidence"],
        all_findings=results["all_findings"],
        assessment=results["assessment"],
    )


def prepare_results(
    target_url,
    nmap_evidence,
    http_evidence,
    all_findings,
    assessment,
    mode,
):
    results = {
        "target_url": target_url,
        "nmap_evidence": nmap_evidence,
        "http_evidence": http_evidence,
        "all_findings": all_findings,
        "assessment": assessment,
        "mode": mode,
    }

    results["pdf_bytes"] = build_pdf(results)
    return results


def analyse_evidence(
    mode,
    nmap_evidence,
    http_evidence,
    findings,
):
    evidence = (
        f"Assessment type: {mode}\n\n"
        "NMAP EVIDENCE:\n"
        + str(nmap_evidence)
        + "\n\nHTTP / STRUCTURED EVIDENCE:\n"
        + json.dumps(http_evidence, indent=2)
        + "\n\nDETERMINISTIC FINDINGS:\n"
        + json.dumps(findings, indent=2)
        + "\n\nIMPORTANT ANALYSIS RULES:\n"
        "Only use the supplied evidence. "
        "Do not invent vulnerabilities, CVEs, "
        "software versions or exploitation results. "
        "Missing security headers do not automatically "
        "confirm exploitable vulnerabilities. "
        "Open ports are not automatically vulnerabilities. "
        "If cookies were not observed, do not assume "
        "the website never uses cookies. "
        "Clearly distinguish observations from "
        "confirmed vulnerabilities. "
        "Recommend safe, non-intrusive follow-up "
        "checks and practical remediation. "
        "Do not claim a complete vulnerability scan "
        "was performed."
    )

    return analyse_finding(evidence)


def identify_mode(http_evidence):
    assessment_type = http_evidence.get(
        "assessment_type", ""
    )

    if assessment_type == "infrastructure":
        return INFRA_MODE

    if assessment_type == "public_web":
        return PUBLIC_WEB_MODE

    return LOCAL_WEB_MODE


# ---------------------------------------------
# Dashboard header
# ---------------------------------------------

st.title("🛡️ VulnAI")

st.caption(
    "AI-Assisted Infrastructure and "
    "Website Security Assessment"
)

st.info(
    "Local infrastructure scanning is restricted "
    "to approved laboratory targets. "
    "Public website mode performs read-only "
    "HTTP configuration checks on authorised "
    "public websites. It is not a comprehensive "
    "penetration test."
)


# ---------------------------------------------
# Sidebar assessment history
# ---------------------------------------------

st.sidebar.title("Assessment History")

history = get_scan_history()

if history:
    history_options = {
        (
            f"#{item['id']} | "
            f"{item['timestamp'][:16]} UTC | "
            f"{item['target_url']}"
        ): item["id"]
        for item in history
    }

    selected_history = st.sidebar.selectbox(
        "Saved Assessments",
        options=list(history_options.keys()),
    )

    if st.sidebar.button(
        "Load Previous Assessment",
        use_container_width=True,
    ):
        try:
            previous = get_assessment(
                history_options[selected_history]
            )

            if previous is None:
                st.sidebar.error(
                    "Assessment not found."
                )
            else:
                previous["mode"] = identify_mode(
                    previous["http_evidence"]
                )

                previous["pdf_bytes"] = build_pdf(
                    previous
                )

                previous["source"] = "history"

                st.session_state[
                    "vulnai_results"
                ] = previous

                st.sidebar.success(
                    "Previous assessment loaded."
                )

        except Exception as error:
            st.sidebar.error(
                f"Could not load assessment: {error}"
            )
else:
    st.sidebar.info(
        "No saved assessments available."
    )


# ---------------------------------------------
# Assessment selection
# ---------------------------------------------

st.subheader("New Security Assessment")

mode = st.radio(
    "Assessment Mode",
    [
        INFRA_MODE,
        LOCAL_WEB_MODE,
        PUBLIC_WEB_MODE,
    ],
    horizontal=True,
)

authorised = False

if mode == INFRA_MODE:
    st.caption(
        "Discover open TCP ports and services "
        "on an approved laboratory target."
    )

    target_input = st.text_input(
        "Authorised Infrastructure IP",
        value="192.168.56.1",
        key="infrastructure_target",
    )

elif mode == LOCAL_WEB_MODE:
    st.caption(
        "Assess the approved local web application "
        "using Nmap, HTTP evidence, security headers, "
        "cookies and CORS checks."
    )

    target_input = st.text_input(
        "Authorised Local Website URL",
        value="http://192.168.56.1:3000/",
        key="local_web_target",
    )

else:
    st.caption(
        "Assess a public website's HTTP configuration "
        "without Nmap, crawling or exploit payloads."
    )

    target_input = st.text_input(
        "Public Website URL",
        value="https://example.com",
        placeholder="https://example.com",
        key="public_web_target",
    )

    authorised = st.checkbox(
        "I confirm that I own this website or have "
        "explicit permission to assess it."
    )

    st.warning(
        "Public website assessment collects "
        "read-only HTTP evidence from the requested "
        "page. It does not verify SQL injection, "
        "XSS, authentication bypass or other "
        "application vulnerabilities."
    )


# ---------------------------------------------
# Execute assessment
# ---------------------------------------------

start_disabled = (
    mode == PUBLIC_WEB_MODE and not authorised
)

if st.button(
    "Start Security Assessment",
    type="primary",
    disabled=start_disabled,
):
    try:
        if mode == INFRA_MODE:

            target = validate_scan_ip(
                target_input
            )

            with st.spinner(
                "Scanning authorised infrastructure..."
            ):
                infrastructure = scan_infrastructure(
                    target
                )

            nmap_evidence = json.dumps(
                infrastructure,
                indent=2,
            )

            all_findings = (
                check_infrastructure_exposure(
                    infrastructure
                )
            )

            http_evidence = {
                "assessment_type": "infrastructure",
                "infrastructure": infrastructure,
            }

            assessment_target = target

        elif mode == LOCAL_WEB_MODE:

            target, port = validate_target(
                target_input
            )

            validate_scan_ip(target)

            with st.spinner(
                "Running authorised local Nmap scan..."
            ):
                raw_output = scan_target(
                    target,
                    port,
                )

                nmap_evidence = clean_scan_output(
                    raw_output
                )

            with st.spinner(
                "Collecting local HTTP evidence..."
            ):
                http_evidence = check_http(
                    target_input
                )

            security_findings = (
                check_security_headers(
                    http_evidence
                )
            )

            cookie_findings = (
                check_cookie_security(
                    http_evidence
                )
            )

            with st.spinner(
                "Checking local CORS configuration..."
            ):
                cors_findings = check_cors(
                    target_input
                )

            all_findings = (
                security_findings
                + cookie_findings
                + cors_findings
            )

            assessment_target = target_input

        else:
            if not authorised:
                raise ValueError(
                    "Target authorisation confirmation "
                    "is required."
                )

            with st.spinner(
                "Collecting public website evidence..."
            ):
                public_result = (
                    assess_public_website(
                        target_input
                    )
                )

            nmap_evidence = (
                "Not performed. Public website "
                "assessment uses read-only HTTP "
                "configuration checks."
            )

            http_evidence = public_result[
                "http_evidence"
            ]

            all_findings = public_result[
                "findings"
            ]

            assessment_target = public_result[
                "target_url"
            ]

        with st.spinner(
            "Analysing findings with local Qwen AI..."
        ):
            assessment = analyse_evidence(
                mode,
                nmap_evidence,
                http_evidence,
                all_findings,
            )

        with st.spinner(
            "Generating PDF report..."
        ):
            results = prepare_results(
                assessment_target,
                nmap_evidence,
                http_evidence,
                all_findings,
                assessment,
                mode,
            )

        assessment_id = save_assessment(
            target_url=assessment_target,
            nmap_evidence=nmap_evidence,
            http_evidence=http_evidence,
            all_findings=all_findings,
            assessment=assessment,
        )

        results["id"] = assessment_id
        results["source"] = "new"

        st.session_state[
            "vulnai_results"
        ] = results

        st.success(
            f"Assessment saved as #{assessment_id}."
        )

    except Exception as error:
        st.error(
            f"Assessment failed: {error}"
        )


# ---------------------------------------------
# Display assessment results
# ---------------------------------------------

if "vulnai_results" in st.session_state:

    results = st.session_state[
        "vulnai_results"
    ]

    st.divider()
    st.subheader("Assessment Results")

    if results.get("source") == "history":
        st.info(
            f"Viewing saved assessment "
            f"#{results['id']}. "
            "No new scan or AI analysis was performed."
        )

    st.write(
        "**Assessment Type:**",
        results["mode"],
    )

    st.write(
        "**Target:**",
        results["target_url"],
    )

    findings = results["all_findings"]

    confirmed = sum(
        1 for finding in findings
        if finding.get(
            "status", ""
        ).lower() == "confirmed"
    )

    needs_verification = sum(
        1 for finding in findings
        if finding.get(
            "status", ""
        ).lower() == "needs verification"
    )

    informational = sum(
        1 for finding in findings
        if finding.get(
            "severity", ""
        ).lower() == "informational"
    )

    st.subheader("Assessment Overview")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Total Observations",
        len(findings),
    )

    col2.metric(
        "Confirmed Vulnerabilities",
        confirmed,
    )

    col3.metric(
        "Needs Verification",
        needs_verification,
    )

    col4.metric(
        "Informational",
        informational,
    )

    st.caption(
        "Status and severity are separate "
        "dimensions and may overlap. "
        "Observations are not automatically "
        "confirmed vulnerabilities."
    )

    st.divider()

    if results["mode"] == INFRA_MODE:

        infrastructure = results[
            "http_evidence"
        ].get("infrastructure", {})

        st.subheader(
            "Infrastructure Exposure"
        )

        st.metric(
            "Open TCP Ports",
            infrastructure.get(
                "open_ports", 0
            ),
        )

        services = infrastructure.get(
            "services", []
        )

        if services:
            st.dataframe(
                services,
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info(
                "No open TCP ports detected "
                "among the selected ports."
            )

        with st.expander(
            "Raw Infrastructure Evidence"
        ):
            st.json(infrastructure)

    elif results["mode"] == LOCAL_WEB_MODE:

        col_a, col_b = st.columns(2)

        with col_a:
            st.subheader("Nmap Results")
            st.code(
                results["nmap_evidence"]
            )

        with col_b:
            st.subheader("HTTP Evidence")
            st.json(
                results["http_evidence"]
            )

    else:
        st.subheader(
            "Public Website HTTP Evidence"
        )

        http_data = results["http_evidence"]

        col_a, col_b, col_c = st.columns(3)

        col_a.metric(
            "HTTP Status",
            http_data.get(
                "status_code", "Unknown"
            ),
        )

        col_b.metric(
            "Cookies Observed",
            len(http_data.get(
                "set_cookie_headers", []
            )),
        )

        col_c.metric(
            "Response Truncated",
            str(http_data.get(
                "response_truncated", False
            )),
        )

        st.write(
            "**Page Title:**",
            http_data.get(
                "page_title", "Not identified"
            ),
        )

        st.write(
            "**Connected IP:**",
            http_data.get(
                "connected_ip", "Unknown"
            ),
        )

        if http_data.get("redirect_location"):
            st.info(
                "Redirect observed but not followed: "
                + str(
                    http_data["redirect_location"]
                )
            )

        with st.expander(
            "Full HTTP Evidence"
        ):
            st.json(http_data)

    st.divider()

    st.subheader("Security Findings")

    if not findings:
        st.info(
            "No findings were produced."
        )

    for finding in findings:
        name = finding.get(
            "name", "Unnamed Finding"
        )

        status = finding.get(
            "status", "Unknown"
        )

        severity = finding.get(
            "severity", "Not Rated"
        )

        with st.expander(
            f"{name} | {status} | "
            f"Severity: {severity}"
        ):
            st.write(
                "**Status:**", status
            )

            st.write(
                "**Severity:**", severity
            )

            st.write(
                "**Evidence:**",
                finding.get(
                    "evidence", "Not available"
                ),
            )

            st.write(
                "**Recommendation:**",
                finding.get(
                    "recommendation",
                    "Not available",
                ),
            )

    st.divider()

    st.subheader(
        "AI Security Investigation"
    )

    st.markdown(
        results["assessment"]
    )

    st.divider()

    st.subheader(
        "Download Assessment Report"
    )

    report_date = datetime.now().strftime(
        "%Y%m%d"
    )

    st.download_button(
        label="📄 Download PDF Report",
        data=results["pdf_bytes"],
        file_name=(
            f"VulnAI_Assessment_"
            f"{results['id']}_"
            f"{report_date}.pdf"
        ),
        mime="application/pdf",
        type="primary",
    )




# ---------------------------------------------
# Saved assessment comparison
# ---------------------------------------------

st.divider()
st.subheader("Saved Assessment Comparison")

st.caption(
    "Compare two saved assessments of the same authorised target. "
    "Comparisons use saved evidence only. No new scans are performed."
)

comparison_type = st.radio(
    "Comparison Type",
    ["Infrastructure", "Website"],
    horizontal=True,
    key="comparison_type",
)

available_history = []

for item in get_scan_history():
    saved = get_assessment(item["id"])

    if saved is None:
        continue

    http_data = saved.get("http_evidence") or {}
    assessment_type = http_data.get("assessment_type")

    if comparison_type == "Infrastructure":
        eligible = assessment_type == "infrastructure"
    else:
        eligible = (
            assessment_type != "infrastructure"
            and bool(http_data.get("url"))
        )

    if eligible:
        available_history.append(item)

if not available_history:
    st.info("No saved assessments available for this comparison type.")

else:
    targets = sorted({
        item["target_url"]
        for item in available_history
    })

    selected_target = st.selectbox(
        "Select Target",
        options=targets,
        key=f"comparison_target_{comparison_type}",
    )

    target_history = sorted(
        [
            item for item in available_history
            if item["target_url"] == selected_target
        ],
        key=lambda item: item["id"],
    )

    if len(target_history) < 2:
        st.info(
            "At least two saved assessments of this target "
            "are required for comparison."
        )

    else:
        comparison_options = {
            (
                f"#{item['id']} | "
                f"{item['timestamp'][:16]} UTC"
            ): item["id"]
            for item in target_history
        }

        labels = list(comparison_options.keys())

        col_old, col_new = st.columns(2)

        with col_old:
            old_selection = st.selectbox(
                "Previous Assessment",
                options=labels,
                index=len(labels) - 2,
                key=f"previous_{comparison_type}_{selected_target}",
            )

        with col_new:
            new_selection = st.selectbox(
                "Current Assessment",
                options=labels,
                index=len(labels) - 1,
                key=f"current_{comparison_type}_{selected_target}",
            )

        old_id = comparison_options[old_selection]
        new_id = comparison_options[new_selection]

        if st.button(
            "Compare Saved Assessments",
            key="run_saved_comparison",
        ):
            st.session_state.pop("vulnai_comparison", None)

            if old_id == new_id:
                st.warning("Please select two different assessments.")

            elif old_id > new_id:
                st.warning(
                    "The previous assessment must be older "
                    "than the current assessment."
                )

            else:
                try:
                    if comparison_type == "Infrastructure":
                        result = compare_assessments(old_id, new_id)
                    else:
                        result = compare_web_assessments(old_id, new_id)

                    st.session_state["vulnai_comparison"] = {
                        "type": comparison_type,
                        "target": selected_target,
                        "old_id": old_id,
                        "new_id": new_id,
                        "result": result,
                    }

                except ValueError as error:
                    st.error(str(error))

        saved = st.session_state.get("vulnai_comparison")

        if (
            saved
            and saved["type"] == comparison_type
            and saved["target"] == selected_target
            and saved["old_id"] == old_id
            and saved["new_id"] == new_id
        ):
            result = saved["result"]

            st.markdown("### Comparison Results")

            st.write("**Target:**", result["target"])
            st.write(
                "**Previous Assessment:**",
                f"#{result['previous_id']}",
            )
            st.write(
                "**Current Assessment:**",
                f"#{result['current_id']}",
            )

            if comparison_type == "Infrastructure":
                col1, col2, col3 = st.columns(3)

                col1.metric(
                    "Newly Opened Ports",
                    len(result["newly_opened"]),
                )
                col2.metric(
                    "No Longer Observed Open",
                    len(result["no_longer_open"]),
                )
                col3.metric(
                    "Unchanged Open Ports",
                    len(result["unchanged_open"]),
                )

                st.write(
                    "**Common Ports Assessed:**",
                    len(result["common_ports_checked"]),
                )

                display_comparison_list(
                    "Newly Opened Ports",
                    result["newly_opened"],
                    "TCP Port",
                )

                display_comparison_list(
                    "No Longer Observed Open",
                    result["no_longer_open"],
                    "TCP Port",
                )

                display_comparison_list(
                    "Unchanged Open Ports",
                    result["unchanged_open"],
                    "TCP Port",
                )

                st.markdown("#### Service Identification Changes")

                if result["service_changes"]:
                    st.dataframe(
                        result["service_changes"],
                        use_container_width=True,
                        hide_index=True,
                    )
                else:
                    st.info(
                        "No service identification changes observed."
                    )

            else:
                col1, col2, col3 = st.columns(3)

                col1.metric(
                    "Added Findings",
                    len(result["added_findings"]),
                )
                col2.metric(
                    "Removed Findings",
                    len(result["removed_findings"]),
                )
                col3.metric(
                    "Changed Findings",
                    len(result["changed_findings"]),
                )

                col_a, col_b = st.columns(2)

                col_a.metric(
                    "Previous HTTP Status",
                    str(result["previous_http_status"]),
                )
                col_b.metric(
                    "Current HTTP Status",
                    str(result["current_http_status"]),
                )

                display_comparison_list(
                    "Added Findings",
                    result["added_findings"],
                    "Finding",
                )

                display_comparison_list(
                    "Removed Findings",
                    result["removed_findings"],
                    "Finding",
                )

                st.markdown("#### Changed Findings")

                if result["changed_findings"]:
                    rows = [
                        {
                            "Finding": item["name"],
                            "Previous Status": item["previous_status"],
                            "Current Status": item["current_status"],
                        }
                        for item in result["changed_findings"]
                    ]

                    st.dataframe(
                        rows,
                        use_container_width=True,
                        hide_index=True,
                    )

                    for finding in result["changed_findings"]:
                        with st.expander(finding["name"]):
                            st.write(
                                "**Previous Evidence:**",
                                finding["previous_evidence"],
                            )
                            st.write(
                                "**Current Evidence:**",
                                finding["current_evidence"],
                            )
                else:
                    st.info("No changed findings observed.")

                display_comparison_list(
                    "Unchanged Findings",
                    result["unchanged_findings"],
                    "Finding",
                )

            st.caption(result["note"])
