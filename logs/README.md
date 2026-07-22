# logs/ — multi-source investigation sample data

Sample data for exercising this repo's multi-source investigation workflow
(endpoint + Azure AD correlation, per `CLAUDE.md`).

- **`windows/`** — real, publicly-sourced Sysmon/Windows Security `.evtx` samples
  (credential access + lateral movement). See `windows/README.md` for provenance and the
  narrative these three files are curated to support.
- **`cloud/`** — **synthetic, fabricated** Azure AD sign-in and audit logs (JSON), hand-written
  for this exercise to plausibly correlate with the endpoint samples (shared username `user01`,
  shared IP `10.0.2.19`, adjoining timeline). Each file carries an explicit
  `_SYNTHETIC_DATA_NOTICE` field. **Not real telemetry — do not treat as genuine IOCs.**

## Suggested correlation exercise

Pivot from the anomalous Azure AD sign-in (`cloud/azuread_signin_synthetic.json`, entry 2) for
`user01@example.corp` back to the on-prem pass-the-hash logon in
`windows/LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx`, using the UPN-prefix ↔
`SubjectUserName`/`TargetUserName` (`user01`) as the join key across the identity schemas, and
forward to the WMI lateral-movement sample in `windows/LM_wmiexec_impacket_sysmon_whoami.evtx`
using the shared IP `10.0.2.19` as the join key. This is the kind of cross-schema, cross-identifier
pivot the `CLAUDE.md` "Log sources" section calls out (SID vs. Azure AD object ID vs. UPN, differing
timestamp conventions) for a per-log-source correlation subagent to make explicit.
