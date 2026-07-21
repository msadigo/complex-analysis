---
source_url: https://www.cisa.gov/news-events/analysis-reports/ar25-338a
report_id: AR25-338A / MAR-251165.c1.v1 (updated through MAR-261234.r1.v1)
report_title: BRICKSTORM Malware Analysis Report
publisher: CISA, NSA, Canadian Centre for Cyber Security (Cyber Centre)
original_publication: 2025-12-04
last_update: 2026-02-11
extraction_date: 2026-07-21
attack_version: "v18"
---

# Threat Intelligence Analysis: BRICKSTORM Backdoor (PRC State-Sponsored)

## Threat Overview

- **Malware family:** BRICKSTORM — a custom ELF backdoor, originally analyzed as Go-based (8 samples) and Rust-based (3 samples, added Dec 19 2025 update), with a newly identified **.NET AOT-compiled variant** (Sample 12, added Feb 11 2026 update). Public reporting also describes Windows versions of the malware, though this MAR's direct analysis focuses on the ELF/VMware-targeting samples.
- **Attribution:** Assessed by CISA/NSA/Cyber Centre as **People's Republic of China (PRC) state-sponsored** cyber actors. The accompanying Sigma rule tags reference `attack.unc5221`, aligning with prior Google Mandiant/Google Cloud reporting on the BRICKSTORM espionage campaign; CrowdStrike reporting referenced in the "Additional Detection Resources" section links related activity to "WARP PANDA."
- **Targets:** VMware vSphere platforms specifically — VMware vCenter servers, VMware ESXi, and VMware Aria Automation Orchestrator — as well as Windows environments. Victim-sector detail was redacted in the extracted content ("primarily in the ‌ and ‌ Sectors"); CISA's report states the intended audience is government and critical infrastructure organizations.
- **Time period:** At the victim organization where CISA performed incident response, PRC actors had **persistent access from at least April 2024 through at least September 3, 2025** (~17 months). The report itself has been iteratively updated four times (Dec 4 2025 → Feb 11 2026) as CISA analyzed additional malware samples (12 total).
- **Notable capability:** Once inside vCenter, actors could steal cloned VM snapshots for offline credential extraction and create hidden, rogue VMs — a technique for durable, hard-to-detect access to virtualized infrastructure.

## TTPs (MITRE ATT&CK v18)

All technique IDs below are explicitly cited in the source report (Appendix A tables + inline citations). Confidence reflects how much operational detail the report provides for that specific use.

### Initial Access
| ATT&CK ID | Technique | Use in Campaign | Confidence |
|---|---|---|---|
| [T1505.003](https://attack.mitre.org/versions/v18/techniques/T1505/003/) | Server Software Component: Web Shell | Actors accessed a DMZ-facing web server via a pre-existing web shell; the report notes it's unknown how initial access to the web server itself was obtained or when the web shell was implanted. | Medium — confirmed use, but the initial-access vector for the web shell itself is unknown |
| [T1078](https://attack.mitre.org/versions/v18/techniques/T1078) | Valid Accounts | Service account credentials were used for lateral movement (RDP); how the second service account's credentials were obtained is unknown. | High |

### Privilege Escalation
| ATT&CK ID | Technique | Use in Campaign | Confidence |
|---|---|---|---|
| [T1548.003](https://attack.mitre.org/versions/v18/techniques/T1548/003/) | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | Used `sudo` to elevate privileges on the vCenter server prior to dropping BRICKSTORM. | High |
| [T1574.007](https://attack.mitre.org/versions/v18/techniques/T1574/007/) | Hijack Execution Flow: Path Interception by PATH Environment Variable | BRICKSTORM's copied instance prepends its own path to `PATH` so it executes before legitimate vSphere binaries of the same name. | High |

### Persistence
| ATT&CK ID | Technique | Use in Campaign | Confidence |
|---|---|---|---|
| [T1037](https://attack.mitre.org/versions/v18/techniques/T1037/) | Boot or Logon Initialization Scripts | Modified the vSphere appliance `init` file in `/etc/sysconfig/` to launch BRICKSTORM at boot. | High |
| T1574.007 | (see above — also functions as a persistence mechanism) | Self-watcher re-copies/re-executes BRICKSTORM and updates `PATH` if the malware is found not running. | High |

### Defense Evasion
| ATT&CK ID | Technique | Use in Campaign | Confidence |
|---|---|---|---|
| [T1036](https://attack.mitre.org/versions/v18/techniques/T1036/) | Masquerading | Samples adopt names mimicking legitimate VMware components (e.g., `vmsrc`/`vmware-sphere`, `updatemgr`, `vami`, `bkmgr`, `vsm-monitordvcenter`, `sqiud` as a typo-squat of `squid`). | High |
| T1548.003 | (see above) | | High |
| T1505.003 | (see above — web shells are also a defense-evasion-friendly persistence mechanism) | | Medium |

### Credential Access
| ATT&CK ID | Technique | Use in Campaign | Confidence |
|---|---|---|---|
| [T1003.003](https://attack.mitre.org/versions/v18/techniques/T1003/003/) | OS Credential Dumping: NTDS | Copied the Active Directory database (`ntds.dit`) from two domain controllers to obtain further credentials (including an MSP account). | High |
| Not ATT&CK-tagged in source, but noted | Compromise of ADFS server and export of cryptographic (token-signing) keys | Actors compromised an ADFS server and exported cryptographic keys — consistent with a Golden SAML–style credential-theft objective (closest mapping: [T1552.004](https://attack.mitre.org/versions/v18/techniques/T1552/004/) Unsecured Credentials: Private Keys). | Low-Medium (inferred mapping, not explicitly cited by CISA) |

### Discovery
| ATT&CK ID | Technique | Use in Campaign | Confidence |
|---|---|---|---|
| [T1083](https://attack.mitre.org/versions/v18/techniques/T1083/) | File and Directory Discovery | BRICKSTORM's `list-dir` command browses the compromised system's filesystem. | High |

### Lateral Movement
| ATT&CK ID | Technique | Use in Campaign | Confidence |
|---|---|---|---|
| [T1021.001](https://attack.mitre.org/versions/v18/techniques/T1021/001/) | Remote Services: RDP | Used RDP with stolen service-account credentials to move from the DMZ web server to domain controllers, and later to vCenter. | High |
| Not ATT&CK-tagged in source, but noted | SMB used to reach two jump servers and the ADFS server (closest mapping: [T1021.002](https://attack.mitre.org/versions/v18/techniques/T1021/002/) SMB/Windows Admin Shares) | Explicitly described in the "Malware Delivery" narrative and Figure 1, but not listed in the Appendix A ATT&CK tables. | Medium (inferred mapping) |
| [T1090.001](https://attack.mitre.org/versions/v18/techniques/T1090/001/) | Proxy: Internal Proxy | BRICKSTORM's SOCKS handler sets up a SOCKS proxy to tunnel traffic and facilitate movement to additional internal systems. | High |

### Collection
| ATT&CK ID | Technique | Use in Campaign | Confidence |
|---|---|---|---|
| Not explicitly tagged | File collection via `get-file`/`list-dir`/`slice-up` commands prior to exfiltration | High (functional, from malware analysis) |

### Command and Control
| ATT&CK ID | Technique | Use in Campaign | Confidence |
|---|---|---|---|
| [T1071.001](https://attack.mitre.org/versions/v18/techniques/T1071/001/) | Application Layer Protocol: Web Protocols | DNS-over-HTTPS (DoH) queries sent as HTTPS requests to legitimate public resolvers (Cloudflare, Google, Quad9, NextDNS) to resolve hard-coded C2 domains without triggering plaintext-DNS detections. | High |
| [T1105](https://attack.mitre.org/versions/v18/techniques/T1105/) | Ingress Tool Transfer | BRICKSTORM dropped onto the vCenter server; malware also supports downloading additional files from C2. | High |
| T1090.001 | (see above) | | High |
| Not explicitly tagged | Multi-layer encrypted C2 (HTTPS → WebSocket upgrade → nested TLS handshake inside the WSS tunnel, `smux`/`Yamux` multiplexing) — closest mapping: [T1573](https://attack.mitre.org/versions/v18/techniques/T1573/) Encrypted Channel / [T1008](https://attack.mitre.org/versions/v18/techniques/T1008/) Fallback Channels (multiplexed virtual streams over one connection) | High (functional, not explicitly ATT&CK-tagged by CISA) |
| Not explicitly tagged | Some samples decrypt hard-coded DoH resolver IPs using XOR; Sample 12 decrypts its WSS address with AES/OpenSSL — closest mapping: [T1027](https://attack.mitre.org/versions/v18/techniques/T1027/) Obfuscated Files or Information | Medium |

### Exfiltration
| ATT&CK ID | Technique | Use in Campaign | Confidence |
|---|---|---|---|
| [T1041](https://attack.mitre.org/versions/v18/techniques/T1041/) | Exfiltration Over C2 Channel | `get-file`/`slice-up` commands exfiltrate files over the established C2 channel. | High |

### Impact
No impact techniques (destructive/disruptive) were described in this report; BRICKSTORM's objective is long-term stealthy access, not disruption.

## Indicators of Compromise

### File Hashes (12 analyzed samples)

| Sample | File Name | MD5 | SHA256 |
|---|---|---|---|
| 1 | vmsrc | 8e4c88d00b6eb46229a1ed7001451320 | aaf5569c8e349c15028bc3fac09eb982efb06eabac955b705a6d447263658e38 |
| 2 | vnetd | 39111508bfde89ce6e0fe6abe0365552 | 013211c56caaa697914b5b5871e4998d0298902e336e373ebb27b7db30917eaf |
| 3 | if-up | dbca28ad420408850a94d5c325183b28 | 57bd98dbb5a00e54f07ffacda1fea91451a0c0b532cd7d570e98ce2ff741c21d |
| 4 | viocli | 0a4fa52803a389311a9ddc49b7b19138 | b3b6a992540da96375e4781afd3052118ad97cfe60ccf004d732f76678f6820a |
| 5 | vts | 82bf31e7d768e6d4d3bc7c8c8ef2b358 | 22c15a32b69116a46eb5d0f2b228cc37cd1b5915a91ec8f38df79d3eed1da26b |
| 6 | vmckd | 18f895e24fe1181bb559215ff9cf6ce3 | f7cda90174b806a34381d5043e89b23ba826abcc89f7abd520060a64475ed506 |
| 7 | (unnamed) | a52e36a70b5e0307cbcaa5fd7c97882c | 39b3d8a8aedffc1b40820f205f6a4dc041cd37262880e5030b008175c45b0c46 |
| 8 | (unnamed) | a02469742f7b0bc9a8ab5e26822b3fa8 | 73fe8b8fb4bd7776362fd356fdc189c93cf5d9f6724f6237d829024c10263fe5 |
| 9 | bkup | 34d6af5ae2ab7a08fa474358a0b95539 | 77b49c854afd6746fee393711b48979376fb910b34105c0e18a3fdc24ea31d5c |
| 10 | vsm-boot-monitordvcenter | d1f608cfb395d9274aa52b6a524d9fb5 | 6a67a9769a55ec889a5dd4199b2fc08965d39d737838836853bc13c81c56a800 |
| 11 | vsm-monitordvcenter | 6c20a810134025a9f05cf312d4b34967 | ed907d39efd5750236b075ca9fbb1f090d7bf578578c38faab24210d298a60ae |
| 12 | support (runs as `sqiud`) | 2654c08491a0f7c4a3dfc6282de5638b | 24a11a26a2586f4fba7bfe89df2e21a0809ad85069e442da98c37c4add369a0c |

Full MD5/SHA1/SHA256/SHA512/ssdeep/entropy values for all 12 samples, plus STIX2 bundles, are published by CISA at the links in the report's "Indicators of Compromise" table (MAR-251165.c1.v1, MAR-2512217.c1.v2, MAR-261234.c1.v1).

Additional SHA256 hashes referenced only inside YARA rule bodies (no accompanying metadata table in this extraction):
`320a0b5d4900697e125cebb5ff03dee7368f8f087db1c1570b0b62f5a986d759`, `dfac2542a0ee65c474b91d3b352540a24f4e223f1b808b741cfe680263f0ee44`, `b91881cb1aa861138f2063ec130b2b01a8aaf0e3f04921e5cbfc61b09024bf12`, `bfb3ffd46b21b2281374cd60bc756fe2dcc32486dcc156c9bd98f24101145454`, `2bf9bfa1f9bcbcad0eada7e3be8d380d809248f08609f6e9d971b37ce09f7e93`, `6d42e9a0757670b9837034b5202d1673093577757b44bb0f0253f366413393e9`, `b30041b986ee3231fd53522c9d0c57e4567d6c60959fa06c125dde2af558fc9f`, `fb22eea57e00b83edad50ee6e02320377efc10586584c476d5018dbba3643c32`, `28a16e782f04d9394b5dfa3363d41d9f5eecc206166aeffd73363d83734a026d`, `0cba5c6d16c7b94a450c36bfbaeab79107ac10aa9548b02c42b4b6ba8cef6a51`

### Network Indicators

- **C2 IP (reused infrastructure):** `149.248.11.71:443` (Sample 12 — CISA notes this is the *first observed instance* of the actor reusing infrastructure in this campaign)
- **C2 domains:** Redacted throughout the report per public reporting that the actors do not reuse C2 domains.
- **Legitimate DoH resolvers abused for C2 resolution** (not malicious themselves — indicators of the *technique*, useful for detection/blocking policy, not blocklisting):
  `1.0.0.1`, `1.1.1.1`, `8.8.4.4`, `8.8.8.8`, `9.9.9.9`, `9.9.9.11`, `149.112.112.11`, `45.90.28.160`, `45.90.30.160`

### File Paths

- `/etc/sysconfig/` and `/etc/sysconfig/network/` — original drop location, modified `init` file
- `/opt/vmware/sbin/vmware-sphere`
- `/usr/java/jre-vmware/bin/updatemgr`
- `/etc/applmgmt/appliance/vami`
- `/usr/sbin/vsm-boot-monitordvcenter`, `/usr/sbin/vsm-monitordvcenter`
- `/usr/sbin/sqiud` (Sample 12, typo-squat of `squid`)
- `/dev/null` (stdio redirection to suppress output)

### C2 API Endpoints / WebSocket Paths

- `wss://[REDACTED].com/api`
- `/rest/apisession` (Sample 12 upgrade endpoint)

### Registry Keys / Email Addresses

None reported as adversary IOCs. (The report lists `contact@cisa.dhs.gov` and `contact@cyber.gc.ca` — these are CISA/Cyber Centre incident-reporting addresses, not threat-actor IOCs.)

## Simulation Plan (Atomic Red Team)

**Caveat:** BRICKSTORM primarily targets Linux-based VMware appliances (vCenter/ESXi/vAAO), while Atomic Red Team's test library skews heavily Windows-focused. Cross-check exact atomic-test availability/OS coverage in your Atomic Red Team install before scheduling — some techniques below may only have Windows-platform atomics and will need Linux-specific custom procedures to faithfully emulate the vSphere-appliance context.

| Priority | ATT&CK ID | Technique | Atomic Red Team Coverage | Notes |
|---|---|---|---|---|
| 1 (High conf. + likely atomics) | T1105 | Ingress Tool Transfer | Yes — atomics for `curl`/`wget`/`certutil`-style downloads | Emulate dropping a binary to `/etc/sysconfig/` via `curl`/`wget` on a Linux target |
| 1 | T1036 | Masquerading | Yes — several atomics (renaming executables, mimicking legitimate binary names) | Use a decoy binary named `updatemgr`/`vami`-style to mimic vSphere components |
| 1 | T1071.001 | Application Layer Protocol: Web Protocols | Yes — atomics for HTTP(S)-based C2 checks | DoH-specific emulation may require a custom atomic (query a public DoH resolver for a test domain) |
| 1 | T1083 | File and Directory Discovery | Yes — simple `ls`/`dir` atomics | Low effort, high fidelity |
| 1 | T1548.003 | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | Yes — Linux sudo-caching/sudo-abuse atomics exist | Validate against vSphere appliance shell restrictions |
| 2 (High conf., check atomics) | T1021.001 | Remote Services: RDP | Yes — atomics exist for RDP-based lateral movement | Test detection of RDP logon from DMZ segment to internal DC |
| 2 | T1003.003 | OS Credential Dumping: NTDS | Yes — atomics for `ntdsutil`/VSS-based `ntds.dit` copy | High-value test; ensure lab DC snapshot/rollback |
| 2 | T1041 | Exfiltration Over C2 Channel | Yes — generic exfil-over-C2 atomics | Pair with T1071.001 test for a realistic chain |
| 2 | T1090.001 | Proxy: Internal Proxy | Partial — SOCKS-proxy-setup atomics exist but Linux-specific ones are sparser | May need custom `ssh -D`/`microsocks`-based proxy atomic to emulate on Linux |
| 3 (Persistence/PrivEsc, check for Linux atomics) | T1037 | Boot or Logon Initialization Scripts | Partial — T1037.004 (RC Scripts) has Linux atomics; verify sub-technique matches an `init`-file-style modification | Best emulated as a custom atomic modifying a test init script in a disposable VM |
| 3 | T1574.007 | Hijack Execution Flow: Path Interception by PATH Environment Variable | Limited — check current index; historically thin coverage | Likely needs a custom atomic: prepend a writable directory to `PATH` and drop a same-named binary |
| 4 (No/limited atomic coverage — note only) | T1505.003 | Server Software Component: Web Shell | Yes for generic web shell placement, but scenario-specific (initial DMZ web-shell access) is better covered by a custom/purple-team scenario than a stock atomic | Consider a tabletop/detection-content review instead of live execution given the ambiguity in the source report about the initial-access vector |
| 4 | T1078 | Valid Accounts | No direct atomic (technique is about usage of legitimate creds, not a discrete executable action) | Emulate via authorized use of a designated test service account for RDP/SMB rather than an "atomic test" |
| Not prioritized (inferred/low-confidence mappings) | T1552.004, T1021.002, T1573, T1027 | (see TTP tables above) | Variable | Lower priority for simulation since these are CLAUDE-inferred mappings, not explicit CISA-stated technique IDs — validate against your own analysis before building detections/tests around them |

### Suggested emulation sequencing (purple team)
1. **Initial foothold simulation:** Deploy a test web shell on a sacrificial DMZ web server (T1505.003) → use test service-account creds for RDP to a lab DC (T1021.001, T1078).
2. **Credential theft:** Copy `ntds.dit` via VSS (T1003.003) from the lab DC.
3. **Lateral movement to virtualization layer:** Simulate SMB-based movement to a jump host (custom, mapped T1021.002) and RDP/console access to a lab vCenter/ESXi appliance if available.
4. **Privilege escalation & persistence on the appliance:** `sudo`-based elevation (T1548.003) → drop a masquerading binary (T1036) → modify a test init script (T1037) → PATH-hijack persistence (T1574.007, likely custom atomic).
5. **C2 emulation:** HTTPS/WSS beacon to a lab-controlled listener (T1071.001), optionally layering a DoH-resolution step against a public resolver in a controlled test-domain scenario.
6. **Exfiltration:** Stage and exfiltrate a test file over the C2 channel (T1041).

Techniques with **no viable stock Atomic Red Team test** for the Linux/vSphere context (T1574.007, T1037 init-script variant, T1090.001 Linux SOCKS) should be flagged to the detection-engineering team as custom-atomic backlog items, prioritized because they map to *high-confidence, explicitly-cited* behaviors in this campaign.

---
*Generated via `/ingest-ti` from CISA AR25-338A. Simulation plans in this document are for authorized detection-engineering/purple-team use only.*
