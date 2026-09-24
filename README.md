# GRC Vulnerability Remediation Validator

Dependency-free Python automation for **VM-01: Timely vulnerability remediation**. It ingests vulnerability evidence, validates remediation timing, evidence freshness/completeness, and risk exceptions, then produces JSON and CSV reports.
## Project structure

```text
grc_vulnerability_control/
├── grc_validator.py
├── README.md
├── sample_data/
│   └── vulnerabilities.csv
└── sample_output/
    ├── grc_report.json
    └── grc_findings.csv
```

- `grc_validator.py`: validation and report-generation logic.
- `sample_data/vulnerabilities.csv`: sample evidence with compliant, non-compliant, and exception scenarios.
- `sample_output/grc_report.json`: detailed machine-readable control report.
- `sample_output/grc_findings.csv`: flattened finding register for Excel, dashboards, filtering, or remediation workflows.

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

## Customize SLA values

PowerShell example:

```powershell
python .\grc_validator.py `
  --input sample_data\vulnerabilities.csv `
  --output-dir output `
  --as-of 2026-09-22 `
  --critical-remediation-days 30 `
  --high-remediation-days 60 `
  --medium-remediation-days 90 `
  --low-remediation-days 180 `
  --evidence-max-age-days 30
```

The same command in one line:

```powershell
python .\grc_validator.py --input sample_data\vulnerabilities.csv --output-dir output --as-of 2026-09-22 --critical-remediation-days 30 --high-remediation-days 60 --medium-remediation-days 90 --low-remediation-days 180 --evidence-max-age-days 30
```

## How the automation works

```text
CSV input
    ↓
Column and date validation
    ↓
Severity-based SLA selection
    ↓
Remediation timing validation
    ↓
Evidence validation
    ↓
Exception validation
    ↓
PASS / FAIL / EXCEPTION
    ↓
Framework and policy mapping
    ↓
JSON, CSV, and terminal output
```

The script reads the CSV one row at a time. Each row represents one vulnerability affecting one system. The `validate()` function evaluates the row and creates a structured finding.

### Step 1: Validate the input

The script checks that the CSV contains the required columns and that dates use `YYYY-MM-DD`.

Required columns:

```text
vulnerability_id
system
severity
discovered_date
status
remediated_date
evidence_id
evidence_date
exception_id
exception_expiry
exception_approved_by
```

If a required column is absent or a date is invalid, the script stops instead of silently producing an unreliable report.

### Step 2: Select the SLA

The vulnerability severity determines the applicable SLA:

```python
sla_by_severity = {
    "CRITICAL": critical_days,
    "HIGH": high_days,
    "MEDIUM": medium_days,
    "LOW": low_days,
}
```

For a remediated vulnerability, the script calculates the number of days from discovery to remediation. For an open or accepted-risk vulnerability, it calculates the number of days from discovery to the assessment date provided through `--as-of`.

### Step 3: Validate remediation timing

The script checks whether:

- the discovery date exists;
- a vulnerability marked `REMEDIATED` has a remediation date;
- the remediation date is not before the discovery date;
- the elapsed time exceeds the severity-based SLA;
- an overdue open item has a valid exception.

Example:

```text
Severity: Critical
Discovered: 2026-08-01
Remediated: 2026-09-10
Elapsed time: 40 days
Applicable SLA: 30 days
Result: REMEDIATION_SLA_EXCEEDED
```

### Step 4: Validate evidence

Evidence is represented by `evidence_id` and `evidence_date`.

The script checks whether:

- both evidence ID and evidence date are present;
- the evidence date is not after the assessment date;
- evidence for a remediated item does not predate remediation;
- evidence is not older than the configured freshness threshold.

The default freshness threshold is 30 days and can be changed with `--evidence-max-age-days`.

Evidence statuses:

- `CURRENT`
- `MISSING`
- `STALE`
- `INVALID`

### Step 5: Validate exceptions

A vulnerability that exceeds its SLA may be classified as `EXCEPTION` when a valid risk exception exists.

A valid exception requires:

- an exception ID;
- an identified approver;
- an expiry date;
- an expiry date on or after the assessment date.

An incomplete or expired exception does not prevent a failed result.

## Result logic

### PASS

A finding is `PASS` when remediation is within SLA, required evidence is acceptable, and no validation reason code is generated.

### FAIL

A finding is `FAIL` when one or more validation rules fail and there is no valid exception covering the condition.

Typical failures include exceeded SLA, missing evidence, stale evidence, invalid dates, and expired exceptions.

### EXCEPTION

A finding is `EXCEPTION` when a control condition is not met but a complete, approved, and unexpired risk exception exists.

`EXCEPTION` is not the same as `PASS`. It shows that the expected condition was not met but the risk was formally accepted for a defined period.

### NOT_IN_SCOPE

`NOT_IN_SCOPE` is reserved for severity values not supported by the configured policy. Critical, high, medium, and low are all evaluated.

## Validation reason codes

| Reason code | Meaning |
|---|---|
| `MISSING_DISCOVERY_DATE` | Discovery date is unavailable, so timeliness cannot be calculated. |
| `INVALID_STATUS` | Status is not `OPEN`, `REMEDIATED`, or `ACCEPTED_RISK`. |
| `MISSING_REMEDIATION_DATE` | Item is marked remediated but has no remediation date. |
| `REMEDIATION_DATE_BEFORE_DISCOVERY` | Remediation date occurs before discovery. |
| `REMEDIATION_SLA_EXCEEDED` | Remediation exceeded the severity-based SLA. |
| `MISSING_EVIDENCE` | Evidence ID or evidence date is missing. |
| `EVIDENCE_DATE_IN_FUTURE` | Evidence date is after the assessment date. |
| `EVIDENCE_BEFORE_REMEDIATION` | Evidence predates remediation. |
| `STALE_EVIDENCE` | Evidence is older than the freshness threshold. |
| `EXCEPTION_MISSING_APPROVAL` | Exception ID or approver information is incomplete. |
| `EXCEPTION_MISSING_EXPIRY` | Exception has no expiry date. |
| `EXCEPTION_EXPIRED` | Exception expired before the assessment date. |
| `OPEN_ITEM_WITHOUT_EXCEPTION` | Open overdue item has no valid exception. |
| `UNSUPPORTED_SEVERITY` | Severity is not supported by the configured policy. |

## Sample input coverage

The sample data contains scenarios for:

- Critical, high, medium, and low severities
- Remediation inside and outside SLA
- Missing and stale evidence
- Evidence before remediation
- Evidence after the assessment date
- Missing discovery or remediation dates
- Valid and expired exceptions
- Open overdue vulnerabilities without exceptions

Additional rows can be added to the same CSV as long as the header and date format remain unchanged.

## Output files

### JSON report

`grc_report.json` contains:

- report metadata;
- overall control result;
- SLA configuration;
- framework and policy mappings;
- summary grouped by result;
- detailed findings;
- reason codes and readable descriptions;
- impacted requirements.

Example:

```json
{
  "vulnerability_id": "CVE-2026-1002",
  "system": "checkout-web-02",
  "severity": "CRITICAL",
  "status": "FAIL",
  "control_id": "VM-01",
  "reason_codes": [
    "REMEDIATION_SLA_EXCEEDED",
    "MISSING_EVIDENCE",
    "OPEN_ITEM_WITHOUT_EXCEPTION"
  ],
  "framework_requirements": [
    {
      "framework": "PCI DSS v4.0.1",
      "requirement": "6.3.3"
    },
    {
      "framework": "Internal Vulnerability Remediation Policy",
      "requirement": "VM-01"
    }
  ]
}
```

### CSV findings register

`grc_findings.csv` contains one row per reason and mapped requirement. This supports:

- Excel filters and pivot tables;
- compliance dashboards;
- remediation tracking;
- evidence reviews;
- grouping by system, severity, reason, or requirement.


## Main validation rules

1. Critical vulnerabilities use a default 30-day SLA and map to PCI DSS 6.3.3 plus VM-01.
2. High vulnerabilities use a default 60-day internal SLA and map to VM-01.
3. Medium vulnerabilities use a default 90-day internal SLA and map to VM-01.
4. Low vulnerabilities use a default 180-day internal SLA and map to VM-01.
5. Evidence requires both an ID and date. Old evidence is `STALE`; logically inconsistent dates are `INVALID`.
6. Exceptions require an ID, approver, and non-expired expiry date.
7. Every supported-severity finding contains `framework_requirements` and readable `reason_details`.

## How to customize the project

### Change default SLA values

Change the defaults in `main()`:

```python
parser.add_argument("--critical-remediation-days", type=int, default=30)
parser.add_argument("--high-remediation-days", type=int, default=60)
parser.add_argument("--medium-remediation-days", type=int, default=90)
parser.add_argument("--low-remediation-days", type=int, default=180)
```

### Add a validation rule

1. Add the required field to the CSV, if necessary.
2. Read the field inside `validate()`.
3. Add the validation condition.
4. Append a reason code to `reasons`.
5. Add a readable description to `REASON_TEXT`.
6. Add one passing and one failing sample row.
7. Regenerate and review the JSON and CSV reports.

Pattern:

```python
if validation_condition:
    reasons.append("NEW_REASON_CODE")
```

Description:

```python
"NEW_REASON_CODE": "Readable explanation of why the validation failed."
```

### Add a field to the output

1. Add the field to the `Finding` dataclass.
2. Supply the value when constructing `Finding(...)`.
3. Add the field to the CSV `fields` list.
4. Add the value to `writer.writerow(...)`.
5. Regenerate and inspect both report files.

## Assumptions and limitations

- The scanner/source correctly classifies severity and scope.
- Evidence authenticity is not cryptographically verified; the script checks metadata completeness, age, and date consistency.
- Exception approval is represented by metadata and is not queried from a GRC or ticketing platform.
- The 60-day high, 90-day medium, and 180-day low SLAs are sample internal-policy values, not direct statements of PCI DSS 6.3.3.
- This supports control testing and reporting; it is not a PCI DSS certification or assessor opinion.
