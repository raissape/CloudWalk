# GRC Vulnerability Remediation Validator

Dependency-free Python automation for **VM-01: Timely vulnerability remediation**. It ingests vulnerability evidence, validates remediation timing, evidence freshness/completeness, and risk exceptions, then produces JSON and CSV reports.

## Framework mapping

- **PCI DSS v4.0.1 Requirement 6.3.3:** critical vulnerabilities are evaluated against a 30-day maximum.
- **Internal Vulnerability Remediation Policy VM-01:** critical, high, medium, and low vulnerabilities are evaluated against configurable SLAs and evidence requirements.
- High, medium, and low findings are not represented as direct PCI DSS 6.3.3 failures. Their default SLAs are sample internal-policy assumptions and can be changed from the command line.

## Run on Windows PowerShell

```powershell
python .\grc_validator.py --input sample_data\vulnerabilities.csv --output-dir output --as-of 2026-09-22
$LASTEXITCODE
```

## Run on Git Bash

```bash
python grc_validator.py --input sample_data/vulnerabilities.csv --output-dir output --as-of 2026-09-22
echo $?
```

Python 3.10+ is required. No third-party packages are needed. Exit code `1` means at least one failed finding; `0` means pass or pass with documented exceptions.

## Outputs

- `grc_report.json`: control result, summary lists, detailed findings, reason descriptions, and framework requirements for every in-scope finding.
- `grc_findings.csv`: one row per reason and mapped requirement, suitable for filters, Excel, dashboards, or issue workflows.

The terminal also prints the exact CVEs and systems by PASS, FAIL, EXCEPTION, and NOT_IN_SCOPE.

## Validation scenarios in the sample

The sample covers PASS, FAIL, and EXCEPTION results across critical, high, medium, and low severities, including overdue remediation, missing or stale evidence, valid and expired exceptions, missing dates, and inconsistent evidence dates.

## Main validation rules

1. Critical vulnerabilities use a default 30-day SLA and map to PCI DSS 6.3.3 plus VM-01.
2. High vulnerabilities use a default 60-day internal SLA and map to VM-01.
3. Medium vulnerabilities use a default 90-day internal SLA and map to VM-01.
4. Low vulnerabilities use a default 180-day internal SLA and map to VM-01.
5. Evidence requires both an ID and date. Old evidence is `STALE`; logically inconsistent dates are `INVALID`.
6. Exceptions require an ID, approver, and non-expired expiry date.
7. Every supported-severity finding contains `framework_requirements` and readable `reason_details`.

## Assumptions and limitations

- The scanner/source correctly classifies severity and scope.
- Evidence authenticity is not cryptographically verified; the script checks metadata completeness, age, and date consistency.
- Exception approval is represented by metadata and is not queried from a GRC or ticketing platform.
- The 60-day high, 90-day medium, and 180-day low SLAs are sample internal-policy values, not direct statements of PCI DSS 6.3.3.
- This supports control testing and reporting; it is not a PCI DSS certification or assessor opinion.
