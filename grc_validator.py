#!/usr/bin/env python3
"""Dependency-free GRC validator for vulnerability-remediation evidence."""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime
from pathlib import Path

PCI_REQUIREMENT = {
    "framework": "PCI DSS v4.0.1",
    "requirement": "6.3.3",
    "requirement_title": "Applicable security patches and updates are installed",
    "applicability": "Critical vulnerabilities must be addressed within one month of release.",
}
POLICY_REQUIREMENT = {
    "framework": "Internal Vulnerability Remediation Policy",
    "requirement": "VM-01",
    "requirement_title": "Timely remediation and evidence retention",
    "applicability": "Critical and high vulnerabilities must meet configured SLAs and retain current evidence.",
}

REASON_TEXT = {
    "MISSING_DISCOVERY_DATE": "The discovery date required to calculate remediation timeliness is missing.",
    "INVALID_STATUS": "The status is not one of OPEN, REMEDIATED, or ACCEPTED_RISK.",
    "MISSING_REMEDIATION_DATE": "The item is marked remediated but has no remediation date.",
    "REMEDIATION_DATE_BEFORE_DISCOVERY": "The remediation date precedes the discovery date.",
    "REMEDIATION_SLA_EXCEEDED": "The vulnerability exceeded the configured remediation SLA.",
    "MISSING_EVIDENCE": "No complete evidence ID and evidence date were supplied.",
    "EVIDENCE_DATE_IN_FUTURE": "The evidence date is after the assessment date.",
    "EVIDENCE_BEFORE_REMEDIATION": "For a remediated item, the evidence predates remediation.",
    "STALE_EVIDENCE": "The evidence is older than the configured freshness threshold.",
    "EXCEPTION_MISSING_APPROVAL": "The exception does not identify an approver.",
    "EXCEPTION_MISSING_EXPIRY": "The exception does not have an expiry date.",
    "EXCEPTION_EXPIRED": "The exception expired before the assessment date.",
    "EXCEPTION_DATE_IN_FUTURE": "The exception expiry date is after the assessment date; this is informational for a valid exception.",
    "OPEN_ITEM_WITHOUT_EXCEPTION": "The open overdue item does not have a valid approved exception.",
}

@dataclass
class Finding:
    vulnerability_id: str
    system: str
    severity: str
    status: str
    control_id: str
    control_name: str
    days_to_remediate_or_open: int | None
    remediation_sla_days: int | None
    evidence_id: str
    evidence_status: str
    exception_id: str
    reason_codes: list[str]
    reason_details: list[dict[str, str]]
    framework_requirements: list[dict[str, str]]


def parse_date(value: str) -> date | None:
    value = (value or "").strip()
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError as exc:
        raise ValueError(f"Invalid date '{value}'; expected YYYY-MM-DD") from exc


def load_rows(path: Path) -> list[dict[str, str]]:
    required = {
        "vulnerability_id", "system", "severity", "discovered_date", "status",
        "remediated_date", "evidence_id", "evidence_date", "exception_id",
        "exception_expiry", "exception_approved_by",
    }
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError("Missing required columns: " + ", ".join(sorted(missing)))
        rows = list(reader)
    if not rows:
        raise ValueError("Input CSV contains no evidence rows")
    return rows


def requirements_for(severity: str) -> list[dict[str, str]]:
    requirements = [POLICY_REQUIREMENT]
    if severity == "CRITICAL":
        requirements.insert(0, PCI_REQUIREMENT)
    return requirements


def validate(row: dict[str, str], as_of: date, critical_days: int,
             high_days: int, medium_days: int, low_days: int,
             evidence_max_age: int) -> Finding:
    vulnerability_id = row["vulnerability_id"].strip() or "MISSING_ID"
    system = row["system"].strip() or "MISSING_SYSTEM"
    severity = row["severity"].strip().upper()
    item_state = row["status"].strip().upper()
    discovered = parse_date(row["discovered_date"])
    remediated = parse_date(row["remediated_date"])
    evidence_id = row["evidence_id"].strip()
    evidence_date = parse_date(row["evidence_date"])
    exception_id = row["exception_id"].strip()
    exception_expiry = parse_date(row["exception_expiry"])
    exception_approver = row["exception_approved_by"].strip()
    reasons: list[str] = []

    sla_by_severity = {
        "CRITICAL": critical_days,
        "HIGH": high_days,
        "MEDIUM": medium_days,
        "LOW": low_days,
    }
    if severity not in sla_by_severity:
        return Finding(vulnerability_id, system, severity, "NOT_IN_SCOPE", "VM-01",
                       "Timely vulnerability remediation", None, None, evidence_id,
                       "NOT_EVALUATED", exception_id, ["UNSUPPORTED_SEVERITY"],
                       [{"code": "UNSUPPORTED_SEVERITY", "description":
                         "The supplied severity is not supported by the control policy."}], [])

    sla_days = sla_by_severity[severity]
    if item_state not in {"OPEN", "REMEDIATED", "ACCEPTED_RISK"}:
        reasons.append("INVALID_STATUS")

    days_elapsed = None
    if not discovered:
        reasons.append("MISSING_DISCOVERY_DATE")
    else:
        comparison_date = remediated if item_state == "REMEDIATED" and remediated else as_of
        days_elapsed = (comparison_date - discovered).days

    if item_state == "REMEDIATED":
        if not remediated:
            reasons.append("MISSING_REMEDIATION_DATE")
        elif discovered and remediated < discovered:
            reasons.append("REMEDIATION_DATE_BEFORE_DISCOVERY")

    if days_elapsed is not None and days_elapsed > sla_days:
        reasons.append("REMEDIATION_SLA_EXCEEDED")

    if not evidence_id or not evidence_date:
        reasons.append("MISSING_EVIDENCE")
        evidence_status = "MISSING"
    elif evidence_date > as_of:
        reasons.append("EVIDENCE_DATE_IN_FUTURE")
        evidence_status = "INVALID"
    elif item_state == "REMEDIATED" and remediated and evidence_date < remediated:
        reasons.append("EVIDENCE_BEFORE_REMEDIATION")
        evidence_status = "INVALID"
    elif (as_of - evidence_date).days > evidence_max_age:
        reasons.append("STALE_EVIDENCE")
        evidence_status = "STALE"
    else:
        evidence_status = "CURRENT"

    has_exception_data = bool(exception_id or exception_expiry or exception_approver)
    if has_exception_data or item_state == "ACCEPTED_RISK":
        if not exception_id:
            reasons.append("EXCEPTION_MISSING_APPROVAL")
        if not exception_approver:
            reasons.append("EXCEPTION_MISSING_APPROVAL")
        if not exception_expiry:
            reasons.append("EXCEPTION_MISSING_EXPIRY")
        elif exception_expiry < as_of:
            reasons.append("EXCEPTION_EXPIRED")

    exception_faults = {"EXCEPTION_MISSING_APPROVAL", "EXCEPTION_MISSING_EXPIRY", "EXCEPTION_EXPIRED"}
    valid_exception = bool(exception_id and exception_approver and exception_expiry and exception_expiry >= as_of)
    substantive_faults = set(reasons) - exception_faults

    if item_state in {"OPEN", "ACCEPTED_RISK"} and days_elapsed is not None and days_elapsed > sla_days and not valid_exception:
        reasons.append("OPEN_ITEM_WITHOUT_EXCEPTION")

    reasons = list(dict.fromkeys(reasons))
    if valid_exception and substantive_faults:
        result = "EXCEPTION"
    elif reasons:
        result = "FAIL"
    else:
        result = "PASS"

    reason_details = [{"code": code, "description": REASON_TEXT[code]} for code in reasons]
    return Finding(
        vulnerability_id, system, severity, result, "VM-01",
        "Timely vulnerability remediation", days_elapsed, sla_days, evidence_id,
        evidence_status, exception_id, reasons, reason_details,
        requirements_for(severity),
    )


def grouped_summary(findings: list[Finding]) -> dict[str, dict]:
    result = {}
    for status in ("PASS", "FAIL", "EXCEPTION", "NOT_IN_SCOPE"):
        items = [f for f in findings if f.status == status]
        result[status.lower()] = {
            "count": len(items),
            "items": [
                {
                    "vulnerability_id": f.vulnerability_id,
                    "system": f.system,
                    "reason_codes": f.reason_codes,
                    "impacted_requirements": [
                        f"{r['framework']} {r['requirement']}" for r in f.framework_requirements
                    ],
                }
                for f in items
            ],
        }
    return result


def print_console_report(report: dict) -> None:
    print("\nGRC Vulnerability Remediation Report")
    print("=" * 38)
    for category, data in report["summary_by_result"].items():
        print(f"\n{category.upper()}: {data['count']}")
        for item in data["items"]:
            suffix = f" | reasons: {', '.join(item['reason_codes'])}" if item["reason_codes"] else ""
            print(f"- {item['vulnerability_id']} | {item['system']}{suffix}")
    print(f"\nOVERALL STATUS: {report['report_metadata']['overall_status']}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate vulnerability-remediation evidence for GRC reporting.")
    parser.add_argument("--input", required=True, type=Path, help="Input CSV")
    parser.add_argument("--output-dir", required=True, type=Path, help="Directory for JSON and CSV reports")
    parser.add_argument("--as-of", type=parse_date, default=date.today(), help="Assessment date YYYY-MM-DD")
    parser.add_argument("--critical-remediation-days", type=int, default=30)
    parser.add_argument("--high-remediation-days", type=int, default=60)
    parser.add_argument("--medium-remediation-days", type=int, default=90)
    parser.add_argument("--low-remediation-days", type=int, default=180)
    parser.add_argument("--evidence-max-age-days", type=int, default=30)
    args = parser.parse_args()

    findings = [validate(row, args.as_of, args.critical_remediation_days,
                         args.high_remediation_days, args.medium_remediation_days,
                         args.low_remediation_days, args.evidence_max_age_days)
                for row in load_rows(args.input)]
    counts = Counter(f.status for f in findings)
    overall = "FAIL" if counts["FAIL"] else ("PASS_WITH_EXCEPTIONS" if counts["EXCEPTION"] else "PASS")
    report = {
        "report_metadata": {
            "generated_at_utc": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "assessment_date": args.as_of.isoformat(),
            "control_id": "VM-01",
            "control_name": "Timely vulnerability remediation",
            "overall_status": overall,
        },
        "control_mapping": {
            "primary_framework_requirement": PCI_REQUIREMENT,
            "supporting_policy_requirement": POLICY_REQUIREMENT,
            "mapping_rationale": (
                "Critical findings test PCI DSS v4.0.1 Requirement 6.3.3. High, medium, and low findings are evaluated "
                "against configurable internal VM-01 SLAs and are not represented as direct PCI 6.3.3 failures."
            ),
        },
        "policy": {
            "critical_remediation_days": args.critical_remediation_days,
            "high_remediation_days": args.high_remediation_days,
            "medium_remediation_days": args.medium_remediation_days,
            "low_remediation_days": args.low_remediation_days,
            "evidence_max_age_days": args.evidence_max_age_days,
        },
        "summary_by_result": grouped_summary(findings),
        "findings": [asdict(f) for f in findings],
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "grc_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    fields = [
        "vulnerability_id", "system", "severity", "status", "control_id", "control_name",
        "days_to_remediate_or_open", "remediation_sla_days", "evidence_id", "evidence_status",
        "exception_id", "reason_code", "reason_description", "framework", "framework_requirement",
        "requirement_title",
    ]
    with (args.output_dir / "grc_findings.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for finding in findings:
            reason_rows = finding.reason_details or [{"code": "", "description": ""}]
            requirement_rows = finding.framework_requirements or [{"framework": "", "requirement": "", "requirement_title": ""}]
            for reason in reason_rows:
                for requirement in requirement_rows:
                    writer.writerow({
                        "vulnerability_id": finding.vulnerability_id,
                        "system": finding.system,
                        "severity": finding.severity,
                        "status": finding.status,
                        "control_id": finding.control_id,
                        "control_name": finding.control_name,
                        "days_to_remediate_or_open": finding.days_to_remediate_or_open,
                        "remediation_sla_days": finding.remediation_sla_days,
                        "evidence_id": finding.evidence_id,
                        "evidence_status": finding.evidence_status,
                        "exception_id": finding.exception_id,
                        "reason_code": reason["code"],
                        "reason_description": reason["description"],
                        "framework": requirement["framework"],
                        "framework_requirement": requirement["requirement"],
                        "requirement_title": requirement["requirement_title"],
                    })

    print_console_report(report)
    return 1 if overall == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
