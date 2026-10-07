# Structured run result (schema version 1)

Select `--output json` for one machine-readable result. The default `human` format and
numeric exit codes are unchanged. The JSON path writes exactly one object and one
trailing newline to stdout, including for handled configuration, lock, and operation
failures. It writes no progress lines, PEM, or debug records to stdout. `--debug` does
not enable diagnostic logging in JSON mode. Argparse errors and abrupt process death
can occur before a result is produced.

`--generate-csr` and `--retrieve-csr` require `--csr-output FILE` in JSON mode.
The validated public CSR goes only to that file. Explicit signed-certificate file
output remains available. Existing files are never overwritten.

## Fields

Every top-level object has these required fields:

| Field | Type and meaning |
| --- | --- |
| `schema_version` | Integer `1`; independent of release and config versions. |
| `product` | String `aruba`. |
| `operation` | `inspect`, `renew_due`, `renew_now`, `generate_csr`, `retrieve_csr`, `sign_csr`, or `install`. |
| `attempt_id` | One UUIDv4 string, generated after CLI parsing and before config or network work. |
| `started_at`, `finished_at` | UTC RFC3339 strings at second precision. |
| `outcome` | Aggregate value from the outcome vocabulary below. |
| `stage` | Stage of the most serious target, or `completed` for a wholly successful run. |
| `manual_recovery_required` | Boolean; true if any selected target needs investigation before retry. |
| `reason_code` | Reason vocabulary below, or `null`. |
| `message` | Bounded, project-generated, one-line operator message. |
| `results` | Array of per-switch objects; empty for failure before target selection. |

Every per-switch object has `target` (configured switch name), `outcome`, `stage`,
`renewal_due` (boolean or `null` if not assessed), `change` (`none`, `confirmed`, or
`possible`), `manual_recovery_required`, `reason_code`, `message`, `certificate`, and
`milestones`. `change` describes a new certificate-related state change in this
invocation. `certificate` is `null` unless validated public certificate material is
available; then it has `fingerprint_sha256` (lowercase hex SHA-256 of DER) and
`expiry_date` (`YYYY-MM-DD`). No timestamp precision is inferred from a date.
Read-only certificate summaries do not supply a fingerprint and remain `null`.

`milestones` always has `csr`, `issuance`, `installation`, `activation`, and `live_tls`.
Each is `not_attempted`, `confirmed`, `failed`, `uncertain`, or `not_applicable`.
`confirmed` requires direct evidence at that stage. In particular, activation means
Aruba installed-state confirmation, and live TLS means a fresh trusted connection
with host identity and exact DER match. `uncertain` records a dispatched action
whose result could not be confirmed.
`csr=confirmed` means a valid pending CSR was observed or created; staged signing
and installation can confirm a CSR that existed before this invocation. In that
case `change=none` until this invocation causes a new certificate-related change.
`csr=failed` can mean that retrieval or validation failed; it does not imply a
CSR generation command was sent.

Outcome values are `success_changed`, `success_no_change`, `success_prepared`,
`attention_due`, `failure_pre_attempt`, `failure_partial`, and `failure_ambiguous`.
Stages are `startup`, `configuration`, `lock`, `inspection`, `decision`, `preflight`,
`csr_generation`, `csr_retrieval`, `signing`, `issued_validation`, `installation`,
`activation`, `live_verification`, `finalization`, and `completed`. Reason codes are
`config_invalid`, `lock_busy`, `lock_failed`, `pending_state`, `inspection_failed`,
`csr_failed`, `signing_failed`, `validation_failed`, `installation_failed`,
`verification_failed`, `recovery_required`, and `unexpected_failure`.

## Aggregation and exits

The aggregate chooses the first selected target at the highest severity:

`failure_ambiguous` > `failure_partial` > `failure_pre_attempt` > `attention_due` >
`success_changed` > `success_prepared` > `success_no_change`.

For a target failure or inspection attention, the top-level stage, reason, and
message come from that target. For an all-success run the top-level stage is
`completed`. The top-level recovery flag is the OR of global and target flags.
Per-target results retain their own stages, so the aggregate stage does not imply
all switches reached it.

Exit `0` means successful operation, including a healthy `--renew-due` no-op.
Exit `1` means read-only inspection found renewal attention. Exit `2` means a
handled failure, including partial or ambiguous state. JSON never changes these
exit codes. A pending CSR found in renewal preflight has no new change in the
invocation but requires manual recovery. A dispatched CSR or installation with
unknown result is ambiguous. Confirmed installation followed by failed live TLS
is partial and requires investigation. No automatic cleanup or rollback follows.

## Examples

The timestamps and UUIDs below are illustrative. A healthy due check:

```json
{
  "schema_version": 1,
  "product": "aruba",
  "operation": "renew_due",
  "attempt_id": "22c3def5-60a7-42e1-af1c-f24be85e71ec",
  "started_at": "2026-10-07T10:00:00Z",
  "finished_at": "2026-10-07T10:00:01Z",
  "outcome": "success_no_change",
  "stage": "completed",
  "manual_recovery_required": false,
  "reason_code": null,
  "message": "Certificate is healthy; no renewal required.",
  "results": [
    {
      "target": "SWITCH-A",
      "outcome": "success_no_change",
      "stage": "completed",
      "renewal_due": false,
      "change": "none",
      "manual_recovery_required": false,
      "reason_code": null,
      "message": "Certificate is healthy; no renewal required.",
      "certificate": null,
      "milestones": {
        "csr": "not_attempted",
        "issuance": "not_attempted",
        "installation": "not_attempted",
        "activation": "not_attempted",
        "live_tls": "not_attempted"
      }
    }
  ]
}
```

A confirmed renewal has all five milestones confirmed:

```json
{
  "schema_version": 1,
  "product": "aruba",
  "operation": "renew_now",
  "attempt_id": "087164d0-e55c-4781-829e-b18d37f13e82",
  "started_at": "2026-10-07T10:00:00Z",
  "finished_at": "2026-10-07T10:00:25Z",
  "outcome": "success_changed",
  "stage": "completed",
  "manual_recovery_required": false,
  "reason_code": null,
  "message": "Certificate renewal verified by live HTTPS.",
  "results": [
    {
      "target": "SWITCH-A",
      "outcome": "success_changed",
      "stage": "completed",
      "renewal_due": null,
      "change": "confirmed",
      "manual_recovery_required": false,
      "reason_code": null,
      "message": "Certificate renewal verified by live HTTPS.",
      "certificate": {
        "fingerprint_sha256": "abababababababababababababababababababababababababababababababab",
        "expiry_date": "2027-01-05"
      },
      "milestones": {
        "csr": "confirmed",
        "issuance": "confirmed",
        "installation": "confirmed",
        "activation": "confirmed",
        "live_tls": "confirmed"
      }
    }
  ]
}
```

A pending CSR preflight failure:

```json
{
  "schema_version": 1,
  "product": "aruba",
  "operation": "renew_now",
  "attempt_id": "bc594544-2098-40ad-9c70-397c4527040f",
  "started_at": "2026-10-07T10:00:00Z",
  "finished_at": "2026-10-07T10:00:01Z",
  "outcome": "failure_pre_attempt",
  "stage": "preflight",
  "manual_recovery_required": true,
  "reason_code": "pending_state",
  "message": "A pending CSR requires manual investigation.",
  "results": [
    {
      "target": "SWITCH-A",
      "outcome": "failure_pre_attempt",
      "stage": "preflight",
      "renewal_due": null,
      "change": "none",
      "manual_recovery_required": true,
      "reason_code": "pending_state",
      "message": "A pending CSR requires manual investigation.",
      "certificate": null,
      "milestones": {
        "csr": "not_attempted",
        "issuance": "not_attempted",
        "installation": "not_attempted",
        "activation": "not_attempted",
        "live_tls": "not_attempted"
      }
    }
  ]
}
```

## Redaction and evolution

Messages are fixed project text. Results do not include credentials, exception
text, device or API responses, CSR or PEM material, subjects, SANs, issuer,
serial, host address, or protocol transcripts. Configured display names are
allowed. JSON escaping protects control characters in those names. Human output
and explicit file output retain their existing policies.

Version 1 may gain optional fields only when older consumers can safely ignore
them. Removing or renaming a required field, changing its type or semantic
meaning, or adding a value to a published closed enum requires a schema version
increment. The version-1 enum vocabularies are frozen.
