---
investigation_date: 2026-07-22
sources:
  - logs/windows/LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx
  - logs/windows/LM_wmiexec_impacket_sysmon_whoami.evtx
  - logs/windows/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx
  - logs/windows/README.md
  - logs/cloud/azuread_signin_synthetic.json
  - logs/cloud/azuread_audit_synthetic.json
analysts:
  - endpoint-analyst (Windows Security / Sysmon)
  - cloud-analyst (Azure AD sign-in / audit)
data_nature: synthetic/lab — see Scope & Data Caveat
---

# Investigation Finding: Multi-Source Lab Scenario — Credential Theft, PtH, Lateral Movement, Cloud Persistence

## Scope & Data Caveat

This dataset is **not a single continuous real-world capture**. Both analyst agents independently flagged the same issue:

- The endpoint `.evtx` files are three independently-dated public lab samples (from `sbousseaden/EVTX-ATTACK-SAMPLES`) spanning 2019-03-17, 2019-03-18, and 2019-04-30, across three different hosts (`PC04`, `PC01`, `IEWIN7`). Per `logs/windows/README.md`, they were stitched together into a *plausible* single-intrusion narrative for this exercise — not one continuous forensic timeline.
- The cloud logs carry an explicit `_SYNTHETIC_DATA_NOTICE` and were hand-authored/re-dated (2026-01-11 / 2026-01-18) to sit narratively downstream of the endpoint events via a shared IOC (`10.0.2.19`).

Findings below describe the **intended exercise storyline**, not a claim of forensically verified same-incident continuity. Timestamps are reported as-is per source (all confirmed UTC) rather than normalized to a single calendar timeline.

## Summary

The scenario depicts credential theft via LSASS memory access (mimikatz) on one host, reuse of the harvested credential via pass-the-hash on a second host, and separately, WMI-based lateral movement (impacket `wmiexec`) to a third host — narratively tied to a cloud-side compromise of the same user identity (`user01`), where an attacker uses legacy authentication to bypass MFA, registers a persistent MFA method, and sets up hidden mailbox forwarding for exfiltration. The two domains (endpoint and cloud) are linked by a shared identity (`user01`) and a shared source IP (`10.0.2.19`).

## Endpoint Findings (Windows Security / Sysmon)

| Time (UTC) | Host | Event | ATT&CK |
|---|---|---|---|
| 2019-03-17 19:37:11 | PC04 | `mimikatz.exe` (run by `IEUser`) opens `lsass.exe` with `GrantedAccess=0x1010` — the access mask used by `sekurlsa::logonpasswords` | T1003.001 |
| 2019-03-18 11:06:25 | PC01 | EventID 1102 — Security event log cleared, subject `EXAMPLE\user01`; ~4s before the PtH logon (medium-confidence anti-forensics; could also be a capture-boundary artifact) | T1070.001 |
| 2019-03-18 11:06:29 | PC01 | 4624 LogonType 9 (NewCredentials), AuthPackage Negotiate, `user01` → `user01` — classic mimikatz `sekurlsa::pth` signature; immediately followed by 4672 granting a full privileged token (SeDebug, SeImpersonate, SeBackup, SeRestore, SeTakeOwnership, SeSecurity, SeLoadDriver, SeSystemEnvironment) | T1550.002, T1134 |
| 2019-03-18 11:06:29–46 | PC01 | `cmd.exe` → `conhost.exe` → `dllhost.exe` spawned under SYSTEM (`PC01$`); CommandLine fields empty (command-line auditing not enabled) — purpose of `dllhost.exe` unresolved | — |
| 2019-04-30 20:32:49 | IEWIN7 | Inbound SMB connection `10.0.2.19:45616` → `IEWIN7:445` | T1021 |
| 2019-04-30 20:32:51 | IEWIN7 | `wmiprvse.exe` (`-secured -Embedding`) → `cmd.exe` chain → `whoami /all`, output relayed via `\\127.0.0.1\ADMIN$\__1556656369.7` (epoch-named, matches connection timestamp) — impacket `wmiexec` pattern, run as `IEWIN7\IEUser` | T1047, T1021.002, T1059.003, T1033 |

**Endpoint IOCs:** identity `EXAMPLE\user01` (SID `S-1-5-21-1587066498-1489273250-1035260531-1106`); hosts `PC04.example.corp`, `PC01.example.corp`, `IEWIN7`; source IP `10.0.2.19`; artifact path `\\127.0.0.1\ADMIN$\__1556656369.7`; `whoami.exe` SHA256 `599EFD455AEEEFE2044A9B597061F271595033F5D0DF2C99DFDBCA8394BBCEC3`; `cmd.exe` SHA256 `17F746D82695FA9B35493B41859D39D786D32B23A9D2E00F4011DEC7A02402AE`.

## Cloud Findings (Azure AD Sign-In / Audit)

| Time (UTC) | Event | ATT&CK |
|---|---|---|
| 2026-01-11 08:14:02 | Baseline legitimate sign-in, `user01@example.corp`, Manchester GB, IP `51.140.22.9`, known compliant device (`USER01-LAPTOP`) | — |
| 2026-01-18 11:19:47 | Anomalous legacy-auth (IMAP/BAV2ROPC) sign-in, `isInteractive: false`, no device info, IP `10.0.2.19`, riskLevel **high**, risk reasons `unfamiliarLocation`/`anonymizedIPAddress` — legacy auth bypasses per-app MFA enforcement | T1078.004, T1556 |
| 2026-01-18 11:24:10 | New MFA phone (`+1 555-0142`) registered on `user01`, same IP, ~4m23s after the risky sign-in | T1098.005 / T1556.006 |
| 2026-01-18 11:26:33 | Hidden inbox-forwarding rule added, target `mail-example-corp-support.com` (lookalike domain), `StopProcessingRules: true`, same IP | T1114.003 |

**Cloud IOCs:** identity `user01@example.corp` (objectId `a1b2c3d4-e5f6-4711-8899-aabbccddeeff`); attacker IP `10.0.2.19`; malicious MFA phone `+1 555-0142`; exfil/BEC domain `mail-example-corp-support.com`; client indicator `BAV2ROPC` / `Other clients; IMAP4`.

## Correlation

- **Identity:** `EXAMPLE\user01` (endpoint SID `S-1-5-21-...-1106`) ↔ `user01@example.corp` (cloud UPN / objectId `a1b2c3d4-...`)
- **IP:** `10.0.2.19` — shared between the wmiexec inbound connection to `IEWIN7:445` and the risky cloud sign-in / MFA registration / inbox-rule events

**Storyline implied by the exercise:** credential dumping on PC04 → pass-the-hash on PC01 → harvested credentials used for a legacy-auth cloud sign-in from `10.0.2.19` → attacker registers persistent MFA → sets up mail exfiltration → `10.0.2.19` separately drives wmiexec-based lateral movement to `IEWIN7`.

## Open Questions

1. What triggered `dllhost.exe` at 11:06:46Z on PC01 (17s after the PtH logon)? CommandLine is empty; check DCOM/OLE or Sysmon Event ID 1 for PC01 if a fuller log is available.
2. What process/account initiated the `Win32_Process.Create` WMI call that spawned `wmiprvse.exe` on IEWIN7? Not visible in this ~3-second log slice.
3. Is `IEUser` on PC04 (mimikatz host) the same account/machine as `IEUser` on IEWIN7 (wmiexec target), or are these two unrelated lab samples being narratively combined? Per the README, treat as unconfirmed.
4. No 4625 (failed logon) events present — no brute-force indicators in this set.
5. No role-assignment, group-membership, app-consent, or service-principal audit events are present in the cloud audit log beyond the MFA registration and inbox rule — a fuller export should be checked if broader privilege-escalation activity is suspected.

## Confidence Summary

| Finding | Confidence |
|---|---|
| LSASS credential dumping (T1003.001) | High |
| Pass-the-hash logon (T1550.002) | High |
| WMI-based lateral movement / impacket wmiexec (T1047/T1021) | High |
| Legacy-auth MFA bypass sign-in | High |
| MFA-method registration as persistence | High |
| Inbox forwarding rule as exfiltration/BEC | High |
| Event-log-clear as anti-forensics | Medium (could be capture artifact) |
| Endpoint↔cloud IP/identity correlation as one real intrusion | High confidence this is the intended exercise narrative; **not** a forensically verified real-world correlation given the synthetic/re-dated nature of the source data
