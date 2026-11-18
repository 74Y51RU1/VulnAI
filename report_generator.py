
from io import BytesIO
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
)


def generate_pdf_report(
    target_url,
    nmap_evidence,
    http_evidence,
    all_findings,
    assessment,
):
    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=42,
        rightMargin=42,
        topMargin=48,
        bottomMargin=48,
        title="VulnAI Security Assessment",
        author="VulnAI",
    )

    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        fontSize=22,
        leading=28,
        textColor=colors.HexColor("#17365D"),
        alignment=TA_CENTER,
        spaceAfter=15,
    ))

    styles.add(ParagraphStyle(
        name="ReportHeading",
        parent=styles["Heading2"],
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#17365D"),
        spaceBefore=14,
        spaceAfter=8,
    ))

    styles.add(ParagraphStyle(
        name="ReportBody",
        parent=styles["BodyText"],
        fontSize=9,
        leading=13,
        spaceAfter=6,
        wordWrap="CJK",
    ))

    styles.add(ParagraphStyle(
        name="ReportTableHeader",
        parent=styles["ReportBody"],
        textColor=colors.white,
        fontName="Helvetica-Bold",
        spaceAfter=0,
    ))

    story = []

    def paragraph(value):
        import re

        text = str(value)
        parts = re.split(r"(\\S{65,})", text)
        formatted = []

        for part in parts:
            if len(part) >= 65 and not any(
                character.isspace() for character in part
            ):
                chunks = [
                    part[index:index + 55]
                    for index in range(0, len(part), 55)
                ]
                formatted.append(
                    "<br/>".join(escape(chunk) for chunk in chunks)
                )
            else:
                formatted.append(escape(part))

        safe_text = "".join(formatted).replace(
            "\\n", "<br/>"
        )

        return Paragraph(
            safe_text,
            styles["ReportBody"],
        )

    def add_text(value):
        story.append(paragraph(value))

    section_number = 0

    def add_section(title):
        nonlocal section_number
        section_number += 1

        story.append(Paragraph(
            escape(f"{section_number}. {title}"),
            styles["ReportHeading"],
        ))

    def footer(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.grey)

        canvas.drawString(
            42,
            28,
            "VulnAI | Security Configuration Assessment",
        )

        canvas.drawRightString(
            A4[0] - 42,
            28,
            f"Page {document.page}",
        )

        canvas.restoreState()

    # --------------------------------------------
    # Assessment mode
    # --------------------------------------------

    assessment_mode = http_evidence.get(
        "assessment_type", ""
    )

    is_infrastructure = (
        assessment_mode == "infrastructure"
    )

    is_public_web = (
        assessment_mode == "public_web"
    )

    if is_infrastructure:
        assessment_type = (
            "Infrastructure Exposure Assessment"
        )
    elif is_public_web:
        assessment_type = (
            "Public Website Security Assessment"
        )
    else:
        assessment_type = (
            "Web Security Assessment"
        )

    # --------------------------------------------
    # Report heading
    # --------------------------------------------

    story.append(Paragraph(
        "VulnAI",
        styles["ReportTitle"],
    ))

    story.append(Paragraph(
        escape(assessment_type),
        styles["Heading2"],
    ))

    story.append(Spacer(1, 12))

    add_text(
        "Report Generated: "
        + datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"
        )
    )

    add_text(f"Target: {target_url}")

    if is_public_web:
        add_text(
            "Scope: Read-only HTTP configuration "
            "assessment of the requested public webpage. "
            "No port scanning or active exploitation."
        )
    else:
        add_text(
            "Scope: Authorised local laboratory."
        )

    # --------------------------------------------
    # Executive summary
    # --------------------------------------------

    add_section("Executive Summary")

    confirmed = sum(
        1
        for finding in all_findings
        if str(
            finding.get("status", "")
        ).lower() == "confirmed"
    )

    needs_verification = sum(
        1
        for finding in all_findings
        if str(
            finding.get("status", "")
        ).lower() == "needs verification"
    )

    add_text(
        f"Recorded observations: {len(all_findings)}. "
        f"Confirmed vulnerabilities: {confirmed}. "
        f"Findings requiring verification: "
        f"{needs_verification}."
    )

    if is_infrastructure:
        infrastructure = http_evidence.get(
            "infrastructure", {}
        )

        checked = infrastructure.get(
            "ports_checked", []
        )

        services = infrastructure.get(
            "services", []
        )

        add_text(
            f"Of {len(checked)} selected TCP ports assessed, "
            f"{len(services)} were observed open. "
            "This does not establish the state of "
            "unscanned ports."
        )

    # --------------------------------------------
    # Security findings
    # --------------------------------------------

    add_section("Security Findings")

    if not all_findings:
        add_text(
            "No findings were produced by "
            "the configured checks."
        )

    for index, finding in enumerate(
        all_findings, 1
    ):
        name = finding.get(
            "name", "Unnamed Finding"
        )

        status = finding.get(
            "status", "Unknown"
        )

        severity = finding.get(
            "severity", "Not Rated"
        )

        content = [
            Paragraph(
                escape(f"{index}. {name}"),
                styles["Heading3"],
            ),
            paragraph(f"Status: {status}"),
            paragraph(f"Severity: {severity}"),
            paragraph(
                "Evidence: "
                + str(finding.get(
                    "evidence", ""
                ))
            ),
            paragraph(
                "Recommendation: "
                + str(finding.get(
                    "recommendation", ""
                ))
            ),
        ]

        story.extend(content)
        story.append(Spacer(1, 8))

    # --------------------------------------------
    # Infrastructure evidence
    # --------------------------------------------

    if is_infrastructure:
        add_section(
            "Infrastructure Scan Evidence"
        )

        infrastructure = http_evidence.get(
            "infrastructure", {}
        )

        services = infrastructure.get(
            "services", []
        )

        add_text(
            "Nmap service labels are observations "
            "and may require independent verification."
        )

        table_data = [[
            "Port",
            "Protocol",
            "Service",
            "Product / Version",
        ]]

        for service in services:
            product_version = " ".join(
                part
                for part in [
                    service.get("product", ""),
                    service.get("version", ""),
                ]
                if part
            ) or "Not identified"

            table_data.append([
                str(service.get("port", "")),
                str(service.get(
                    "protocol", "tcp"
                )),
                str(service.get(
                    "service", "unknown"
                )),
                product_version,
            ])

        if len(table_data) == 1:
            add_text(
                "No open ports detected among "
                "the selected ports."
            )
        else:
            formatted_rows = []

            for index, row in enumerate(
                table_data
            ):
                if index == 0:
                    formatted_rows.append([
                        Paragraph(
                            escape(str(cell)),
                            styles["ReportTableHeader"],
                        )
                        for cell in row
                    ])
                else:
                    formatted_rows.append([
                        paragraph(cell)
                        for cell in row
                    ])

            table = Table(
                formatted_rows,
                colWidths=[52, 65, 100, 294],
                repeatRows=1,
                hAlign="LEFT",
            )

            table.setStyle(TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#17365D"),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [
                        colors.white,
                        colors.HexColor("#F2F5F9"),
                    ],
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
            ]))

            story.append(table)

        checked = infrastructure.get(
            "ports_checked", []
        )

        add_text(
            "TCP ports assessed: "
            + ", ".join(map(str, checked))
        )

    # --------------------------------------------
    # Website HTTP evidence
    # --------------------------------------------

    else:
        if not is_public_web:
            add_section("Nmap Scan Evidence")
            add_text(nmap_evidence)

        add_section("HTTP Evidence")

        add_text(
            "URL: "
            + str(http_evidence.get(
                "url", "Unknown"
            ))
        )

        add_text(
            "HTTP Status: "
            + str(http_evidence.get(
                "status_code", "Unknown"
            ))
        )

        add_text(
            "Page Title: "
            + str(http_evidence.get(
                "page_title", "Unknown"
            ))
        )

        if is_public_web:
            add_text(
                "Connected Public IP: "
                + str(http_evidence.get(
                    "connected_ip", "Unknown"
                ))
            )

            add_text(
                "Response Truncated: "
                + str(http_evidence.get(
                    "response_truncated", False
                ))
            )

            redirect_location = (
                http_evidence.get(
                    "redirect_location"
                )
            )

            if redirect_location:
                add_text(
                    "Redirect Location (not followed): "
                    + str(redirect_location)
                )

        for key, value in http_evidence.get(
            "headers", {}
        ).items():
            add_text(f"{key}: {value}")

        if is_public_web:
            cookies = http_evidence.get(
                "set_cookie_headers", []
            )

            add_text(
                "Set-Cookie Headers Observed: "
                + str(len(cookies))
            )

    # --------------------------------------------
    # AI investigation
    # --------------------------------------------

    add_section("AI Security Investigation")

    for line in str(assessment).splitlines():
        line = line.strip()

        if not line:
            story.append(Spacer(1, 5))

        elif line.startswith("#"):
            story.append(Paragraph(
                escape(
                    line.lstrip("#").strip()
                ),
                styles["Heading3"],
            ))

        else:
            add_text(line)

    # --------------------------------------------
    # Assessment limitations
    # --------------------------------------------

    add_section("Assessment Limitations")

    if is_public_web:
        add_text(
            "This assessment examines the HTTP response "
            "of the requested public webpage only. "
            "It does not crawl the website, test "
            "authentication, exploit vulnerabilities, "
            "or perform network port scanning. "
            "Missing security headers and cookie "
            "attributes are observations, not "
            "confirmed vulnerabilities. "
            "AI recommendations require independent "
            "analyst verification."
        )
    else:
        add_text(
            "This is a targeted, non-destructive "
            "assessment of an authorised lab target. "
            "It is not a comprehensive penetration test. "
            "Service identification may be uncertain. "
            "AI recommendations require analyst review. "
            "Findings must be independently validated "
            "before being treated as confirmed "
            "vulnerabilities."
        )

    # --------------------------------------------
    # Generate PDF
    # --------------------------------------------

    doc.build(
        story,
        onFirstPage=footer,
        onLaterPages=footer,
    )

    buffer.seek(0)

    return buffer.getvalue()
