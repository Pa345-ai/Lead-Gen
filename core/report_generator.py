# core/report_generator.py
"""
Report Generator — Turns VerificationResult objects into actionable reports.

Output formats:
  - Markdown (per-finding and summary)
  - JSON (machine-readable for CI/CD)
  - PDF (via ReportLab, executive summary + finding details)
  - HackerOne submission format (single finding)

Designed to match the quality bar of professional penetration test reports.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from core.graph import StateGraph, EndpointNode
from core.executor import VerificationResult, VerificationStatus, ImpactLevel


# ─── CVSS Helper ─────────────────────────────────────────────────────────────

def estimate_cvss(vuln_class: str, impact: ImpactLevel) -> tuple[float, str]:
    """Return (score, vector) for common vulnerability classes."""
    cvss_map = {
        "IDOR": (7.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
        "MissingAuthentication": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        "AuthBypassPathAsymmetry": (8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
        "MassAssignment": (8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H"),
        "UnauthenticatedWrite": (8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H"),
        "DataLeakIDOR": (6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
    }
    score, vector = cvss_map.get(vuln_class, (5.0, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"))
    # Adjust based on actual impact level
    impact_mult = {
        ImpactLevel.NONE: 0.0,
        ImpactLevel.LOW: 0.7,
        ImpactLevel.MEDIUM: 0.85,
        ImpactLevel.HIGH: 1.0,
        ImpactLevel.CRITICAL: 1.15,
    }
    adjusted = min(10.0, score * impact_mult.get(impact, 1.0))
    return round(adjusted, 1), vector


def severity_label(cvss_score: float) -> str:
    if cvss_score >= 9.0:
        return "Critical"
    elif cvss_score >= 7.0:
        return "High"
    elif cvss_score >= 4.0:
        return "Medium"
    else:
        return "Low"


# ─── Curl command generator ─────────────────────────────────────────────────

def curl_from_request_log(entry: dict, base_url: str = "") -> str:
    """Convert a request log entry into a curl command."""
    method = entry.get("request", "GET").split()[0] if entry.get("request") else "GET"
    url = base_url + (entry.get("request", "").split(" ", 1)[1] if " " in entry.get("request", "") else "")
    headers = entry.get("headers_sent", {})
    curl = f"curl -X {method} '{url}'"
    for k, v in headers.items():
        if k.lower() not in ("host", "user-agent", "content-length"):
            curl += f" \\\n  -H '{k}: {v}'"
    body = entry.get("response_body", "")
    if body and method in ("POST", "PUT", "PATCH"):
        curl += f" \\\n  -d '{body[:200]}'"
    return curl


# ─── Report Generator ────────────────────────────────────────────────────────

class ReportGenerator:
    def __init__(self, output_dir: str = "./output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ── Markdown Reports ─────────────────────────────────────────────────

    def generate_markdown_summary(
        self,
        hypotheses: list,
        graph: StateGraph,
        target_name: str = "Target Application",
    ) -> str:
        """Generate a markdown summary of all hypotheses (pre-execution)."""
        lines = [
            f"# SecureGraph — Vulnerability Hypotheses",
            f"",
            f"**Target:** {target_name}",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Total Hypotheses:** {len(hypotheses)}",
            f"",
            f"---",
            f"",
            f"## Summary by Severity",
            f"",
        ]

        sev_counts = {}
        for h in hypotheses:
            sev = h.severity_estimate
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        for sev in ["Critical", "High", "Medium", "Low"]:
            count = sev_counts.get(sev, 0)
            lines.append(f"- **{sev}:** {count}")

        lines.extend(["", "---", "", "## All Hypotheses", ""])

        for i, h in enumerate(hypotheses, 1):
            ep = graph.get_node(h.endpoint_id)
            path = ep.path if isinstance(ep, EndpointNode) else h.endpoint_id
            lines.extend([
                f"### [{i}] {h.vuln_class} — {h.severity_estimate}",
                f"",
                f"- **Endpoint:** `{path}`",
                f"- **Confidence:** {h.confidence:.0%}",
                f"- **Description:** {h.description}",
                f"- **Attack:** {h.attack_transform}",
                f"",
                f"**Evidence:**",
            ])
            for ev in h.evidence:
                lines.append(f"  - {ev}")
            lines.append("")

        md_content = "\n".join(lines)
        path = self.output_dir / "hypotheses.md"
        path.write_text(md_content)
        return md_content

    def generate_finding_report(
        self,
        result: VerificationResult,
        graph: StateGraph,
        finding_number: int = 1,
    ) -> str:
        """Generate a detailed markdown report for a single confirmed finding."""
        cvss_score, cvss_vector = estimate_cvss(result.vuln_class, result.impact)
        sev = severity_label(cvss_score)
        ep = graph.get_node(result.endpoint_id)
        path = ep.path if isinstance(ep, EndpointNode) else result.endpoint_id

        lines = [
            f"# Finding #{finding_number}: {result.vuln_class}",
            f"",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Severity** | {sev} ({cvss_score}/10) |",
            f"| **CVSS Vector** | `{cvss_vector}` |",
            f"| **Endpoint** | `{path}` |",
            f"| **Status** | {result.status.value.upper()} |",
            f"| **Impact** | {result.impact.value} |",
            f"",
            f"---",
            f"",
            f"## Description",
            f"",
            f"Automated exploit verification confirmed {result.vuln_class} on the endpoint "
            f"`{path}`. The vulnerability allows an attacker to bypass intended access controls.",
            f"",
            f"## Evidence",
            f"",
        ]
        for ev in result.evidence:
            lines.append(f"- {ev}")

        lines.extend([
            f"",
            f"## Steps to Reproduce",
            f"",
        ])
        for i, entry in enumerate(result.request_log, 1):
            lines.extend([
                f"### Step {i}",
                f"```bash",
                curl_from_request_log(entry),
                f"```",
                f"",
                f"**Response Status:** {entry.get('status', 'N/A')}",
                f"",
                f"**Response Body:**",
                f"```json",
                entry.get('response_body', '')[:500],
                f"```",
                f"",
            ])

        lines.extend([
            f"## Remediation",
            f"",
            self._remediation_advice(result.vuln_class),
            f"",
            f"---",
            f"*Generated by SecureGraph on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*",
        ])

        md_content = "\n".join(lines)
        filename = f"finding_{finding_number:03d}_{result.vuln_class.lower()}.md"
        (self.output_dir / filename).write_text(md_content)
        return md_content

    def _remediation_advice(self, vuln_class: str) -> str:
        advice = {
            "IDOR": (
                "Implement object-level authorization checks. Before returning or modifying "
                "any resource, verify that the requesting user has permission to access it. "
                "Use a pattern like `if resource.owner_id != current_user.id: raise Forbidden()` "
                "or implement a policy engine that checks ownership at the data access layer."
            ),
            "MissingAuthentication": (
                "Add authentication requirements to this endpoint. In FastAPI, add "
                "`current_user: User = Depends(get_current_user)` to the function signature. "
                "For Django, add `@login_required` or `permission_classes = [IsAuthenticated]`."
            ),
            "AuthBypassPathAsymmetry": (
                "Ensure consistent authentication enforcement across all HTTP methods on the same "
                "resource path. If GET requires admin, POST/PUT/DELETE must also require admin. "
                "Apply auth middleware at the router level rather than per-route."
            ),
            "MassAssignment": (
                "Never trust client-supplied ownership fields. Set `owner_id`, `user_id`, "
                "`tenant_id` server-side from the authenticated session. Use Pydantic's "
                "`exclude` parameter or SQLAlchemy's `exclude` on column definitions to prevent "
                "mass assignment of sensitive fields."
            ),
            "UnauthenticatedWrite": (
                "Require authentication for any endpoint that modifies data. Add an auth "
                "dependency and verify the caller's identity before executing database writes."
            ),
            "DataLeakIDOR": (
                "Filter query results by the authenticated user's ownership scope. Use "
                "`.filter(owner_id=current_user.id)` on all database queries that return "
                "user-specific data. Never return unfiltered collections to end users."
            ),
        }
        return advice.get(vuln_class, "Review access controls for this endpoint and ensure proper authorization is enforced.")

    # ── Full Report ───────────────────────────────────────────────────────

    def generate_full_report(
        self,
        verified: list[VerificationResult],
        all_results: list[VerificationResult],
        graph: StateGraph,
        target_name: str = "Target Application",
    ) -> str:
        """Generate a comprehensive markdown report with all findings."""
        lines = [
            f"# SecureGraph — Security Assessment Report",
            f"",
            f"**Target:** {target_name}",
            f"**Assessment Date:** {datetime.now().strftime('%Y-%m-%d')}",
            f"**Tool Version:** SecureGraph 1.0",
            f"",
            f"---",
            f"",
            f"## Executive Summary",
            f"",
        ]

        if verified:
            critical = len([r for r in verified if r.impact in (ImpactLevel.CRITICAL, ImpactLevel.HIGH)])
            lines.extend([
                f"SecureGraph identified **{len(verified)} verified security vulnerabilities** "
                f"in {target_name}, including **{critical} high/critical severity** issues "
                f"that require immediate remediation.",
                f"",
                f"### Verified Vulnerabilities",
                f"",
            ])
            for r in verified:
                cvss, _ = estimate_cvss(r.vuln_class, r.impact)
                lines.append(f"- **[{severity_label(cvss)}]** {r.vuln_class} — `{r.endpoint_id}`")
        else:
            lines.append("No vulnerabilities were verified during this assessment.")

        lines.extend([
            f"",
            f"### Assessment Statistics",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total endpoints analyzed | {len(graph.endpoints())} |",
            f"| Hypotheses generated | {len(all_results)} |",
            f"| Verified | {len(verified)} |",
            f"| Disproved | {len([r for r in all_results if r.status == VerificationStatus.DISPROVED])} |",
            f"| Inconclusive | {len([r for r in all_results if r.status == VerificationStatus.INCONCLUSIVE])} |",
            f"",
            f"---",
            f"",
        ])

        # Detailed findings
        for i, r in enumerate(verified, 1):
            lines.append(self.generate_finding_report(r, graph, i))
            lines.append("")

        md_content = "\n".join(lines)
        (self.output_dir / "full_report.md").write_text(md_content)
        return md_content

    # ── HackerOne Format ──────────────────────────────────────────────────

    def generate_hackerone_report(self, result: VerificationResult, graph: StateGraph) -> str:
        """Generate a single-finding report in HackerOne submission format."""
        cvss_score, cvss_vector = estimate_cvss(result.vuln_class, result.impact)
        sev = severity_label(cvss_score)
        ep = graph.get_node(result.endpoint_id)
        path = ep.path if isinstance(ep, EndpointNode) else result.endpoint_id

        lines = [
            f"# {result.vuln_class} on {path}",
            f"",
            f"## Summary",
            f"",
            f"Automated exploit verification confirmed {result.vuln_class} on `{path}`. "
            f"This vulnerability allows an attacker to bypass access controls.",
            f"",
            f"## Steps to Reproduce",
            f"",
        ]
        for i, entry in enumerate(result.request_log, 1):
            lines.append(f"{i}. Send the following request:")
            lines.append(f"```bash")
            lines.append(curl_from_request_log(entry))
            lines.append(f"```")
            lines.append(f"   Response: HTTP {entry.get('status', 'N/A')}")
            lines.append("")

        lines.extend([
            f"## Impact",
            f"",
            self._hackerone_impact(result.vuln_class),
            f"",
            f"## Supporting Material",
            f"",
            f"- **CVSS Score:** {cvss_score}/10 ({sev})",
            f"- **CVSS Vector:** `{cvss_vector}`",
            f"- **Evidence count:** {len(result.evidence)} items",
        ])

        md = "\n".join(lines)
        (self.output_dir / f"hackerone_{result.vuln_class.lower()}.md").write_text(md)
        return md

    def _hackerone_impact(self, vuln_class: str) -> str:
        impacts = {
            "IDOR": "An attacker can access or modify resources belonging to other users by manipulating object identifiers. This can lead to unauthorized data disclosure, account takeover, or data loss.",
            "MissingAuthentication": "Any unauthenticated user can perform write operations on the application. This can lead to data tampering, resource deletion, or injection of malicious content.",
            "AuthBypassPathAsymmetry": "An attacker can bypass authentication requirements on specific HTTP methods, gaining access to privileged functionality without credentials.",
            "MassAssignment": "An attacker can set arbitrary ownership fields on resources, effectively hijacking objects belonging to other users or escalating privileges.",
            "UnauthenticatedWrite": "External actors can write to the database without authentication, potentially corrupting data or injecting malicious records.",
        }
        return impacts.get(vuln_class, "Unauthorized access to protected functionality.")

    # ── JSON Export ───────────────────────────────────────────────────────

    def export_json(self, results: list[VerificationResult], graph: StateGraph) -> str:
        """Export all results as machine-readable JSON for CI/CD integration."""
        output = {
            "metadata": {
                "tool": "SecureGraph",
                "version": "1.0",
                "generated": datetime.now().isoformat(),
                "total_findings": len([r for r in results if r.status == VerificationStatus.VERIFIED]),
            },
            "findings": []
        }
        for r in results:
            cvss, vector = estimate_cvss(r.vuln_class, r.impact)
            finding = {
                "vuln_class": r.vuln_class,
                "endpoint_id": r.endpoint_id,
                "status": r.status.value,
                "impact": r.impact.value,
                "cvss_score": cvss,
                "cvss_vector": vector,
                "severity": severity_label(cvss),
                "evidence": r.evidence,
                "error": r.error,
            }
            output["findings"].append(finding)

        json_str = json.dumps(output, indent=2)
        (self.output_dir / "results.json").write_text(json_str)
        return json_str

    # ── PDF Report ────────────────────────────────────────────────────────

    def generate_pdf_report(
        self,
        verified: list[VerificationResult],
        all_results: list[VerificationResult],
        graph: StateGraph,
        target_name: str = "Target Application",
    ) -> str:
        """Generate a PDF report using ReportLab."""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib.colors import HexColor
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

            path = str(self.output_dir / "full_report.pdf")
            doc = SimpleDocTemplate(path, pagesize=A4)
            styles = getSampleStyleSheet()
            story = []

            # Title
            title_style = ParagraphStyle('Title', parent=styles['Title'], fontSize=18)
            story.append(Paragraph(f"Security Assessment Report", title_style))
            story.append(Paragraph(f"{target_name}", styles['Heading2']))
            story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles['Normal']))
            story.append(Spacer(1, 0.2 * inch))

            # Summary table
            critical_count = len([r for r in verified if r.impact in (ImpactLevel.CRITICAL,)])
            high_count = len([r for r in verified if r.impact == ImpactLevel.HIGH])
            table_data = [
                ["Severity", "Count"],
                ["Critical", str(critical_count)],
                ["High", str(high_count)],
                ["Medium", str(len([r for r in verified if r.impact == ImpactLevel.MEDIUM]))],
                ["Low", str(len([r for r in verified if r.impact == ImpactLevel.LOW]))],
            ]
            table = Table(table_data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#333')),
                ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#FFF')),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#CCC')),
            ]))
            story.append(table)
            story.append(Spacer(1, 0.3 * inch))

            # Per-finding summaries
            for i, r in enumerate(verified, 1):
                cvss, _ = estimate_cvss(r.vuln_class, r.impact)
                story.append(Paragraph(f"Finding {i}: {r.vuln_class}", styles['Heading2']))
                story.append(Paragraph(f"<b>Severity:</b> {severity_label(cvss)} (CVSS {cvss}/10)", styles['Normal']))
                story.append(Paragraph(f"<b>Endpoint:</b> {r.endpoint_id}", styles['Normal']))
                story.append(Paragraph(f"<b>Impact:</b> {r.impact.value}", styles['Normal']))
                story.append(Paragraph(r.evidence[0] if r.evidence else "No evidence recorded.", styles['Normal']))
                story.append(Spacer(1, 0.2 * inch))

            doc.build(story)
            return path
        except ImportError:
            print("[!] ReportLab not installed — skipping PDF generation")
            return ""
