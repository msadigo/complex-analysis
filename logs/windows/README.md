# Windows/Sysmon sample logs

These are **real** third-party detection-engineering sample `.evtx` files, copied unmodified
from `sbousseaden/EVTX-ATTACK-SAMPLES` (vendored locally at
`C:\Users\USER\mcp-hayabusa\sample_evtx\EVTX-ATTACK-SAMPLES\`). They are public lab/test
captures used widely for SIEM rule testing — not telemetry from any real organization.

Each file was captured independently (different lab host, different date) as an isolated
technique demo. They are grouped here to form a **plausible** single-intrusion narrative for
the multi-source investigation exercise in this repo, not a literal continuous packet/event
capture of one incident. Field values below (hostnames, usernames, timestamps, IPs) are the
*actual* values recorded in each file.

## Files, in narrative order

1. **`sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx`**
   Sysmon Event ID 10 (ProcessAccess) — `mimikatz.exe` (run by local user `IEUser`) opens a
   handle into `lsass.exe` on host **`PC04.example.corp`**, 2019-03-17 19:37:11 UTC. This
   represents the attacker harvesting cached credentials (including, for this exercise,
   `user01`'s hash) from a workstation `user01` had previously logged into.

2. **`LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx`**
   Windows Security Event ID 4624 (Logon Type 9, NewCredentials) for **`EXAMPLE\user01`**
   (SID `S-1-5-21-1587066498-1489273250-1035260531-1106`) on host **`PC01.example.corp`**,
   2019-03-18 11:06:29 UTC — the "source machine" side of a pass-the-hash operation, i.e. the
   attacker uses `user01`'s harvested NTLM hash to spawn a new logon session impersonating
   `user01` for outbound authentication. This is the pivot point correlated against the
   synthetic Azure AD sign-in in `logs/cloud/`.

3. **`LM_wmiexec_impacket_sysmon_whoami.evtx`**
   Sysmon Event IDs 3 (Network Connection) and 1 (Process Create) on host **`IEWIN7`**,
   2019-04-30 20:32:49–52 UTC — an inbound SMB (445) connection from **`10.0.2.19`**
   followed by `wbem\wmiprvse.exe` spawning `cmd.exe` → `whoami /all` (classic
   impacket `wmiexec.py` pattern). Represents later-stage lateral movement/recon using the
   same attacker-side IP (`10.0.2.19`) reused in the synthetic cloud sign-in log, tying the
   cloud and endpoint activity together across the exercise's extended timeline.

## Correlation notes for the investigation exercise

- **User identity thread:** `EXAMPLE\user01` / `user01@example.corp` (files 2 → cloud logs).
- **IP thread:** `10.0.2.19` (file 3 → cloud sign-in log).
- File 1 and file 3 use a different local demo account (`IEUser`) than the SID-bearing
  domain account in file 2 — expected, since these are independently-sourced public
  samples. Treat file 1/3 as "the attacker's foothold machine" activity and file 2 as
  the moment the specific `user01` identity is confirmed compromised.
