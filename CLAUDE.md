# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

This project builds Claude Code slash commands and subagents for cybersecurity threat intelligence and investigation work. There is no application code, build system, or test suite — the deliverables are prompt-driven workflows (slash commands in `.claude/commands/`, subagents in `.claude/agents/`) that operationalize repeatable analysis tasks.

The project supports two workflows:

1. **Threat intel processing** — ingest threat intel reports, extract TTPs (tactics, techniques, procedures — typically mapped to MITRE ATT&CK), and produce simulation/emulation plans from them.
2. **Multi-source investigation** — correlate endpoint and cloud log sources to investigate security incidents.

## Log sources

Investigation workflows are built around four log sources:

- Windows Security events
- Sysmon events
- Azure AD sign-in logs
- Azure AD audit logs

When designing correlation logic (e.g., a subagent that pivots from a sign-in anomaly to endpoint process activity), account for the differing schemas, timestamp formats/timezones, and identifier fields (e.g., user SID vs. Azure AD object ID vs. UPN) across these sources so correlation steps explicitly state which fields are used to join events.

## Architecture direction

- **Slash commands** (`.claude/commands/`) should encapsulate repeatable, invokable workflows — e.g., a command that takes a raw threat intel report and drives the extraction-to-simulation-plan pipeline, or a command that kicks off a multi-source investigation given an initial lead (an alert, a user, a host, a time window).
- **Subagents** (`.claude/agents/`) should be used for focused, delegable sub-tasks within those workflows — e.g., a TTP-extraction agent, a per-log-source correlation agent — so the top-level command can orchestrate without flooding its own context with raw log data or report text.
- Keep the two workflows' commands/agents organized so it's clear which pipeline (threat intel processing vs. multi-source investigation) a given command or agent belongs to, since they share log-source and TTP knowledge but have different end goals (a simulation plan vs. an investigation finding).

## Commands implemented so far

- `/ingest-ti <url>` (`.claude/commands/ingest-ti.md`) — the full threat-intel pipeline in one command: pulls a report through `defuddle`, extracts TTPs (mapped to MITRE ATT&CK) and IOCs, and drafts an Atomic Red Team-based simulation plan. Saves a structured markdown file to `analysis/ti-[date]-[campaign-name].md`.

### External dependency: defuddle

`defuddle` (the `defuddle-cli` npm package was merged into `defuddle`; install globally with `npm install -g defuddle`) extracts clean article content from HTML pages/files, stripping navigation, ads, and boilerplate. Invoked as `defuddle parse -m <url>` (requires the `parse` subcommand; there is no `--format` flag). This is the standard way reports get into the pipeline — don't hand-scrape or paste raw HTML into context.

## Handling sensitive data

Threat intel reports and log exports handled by this project may contain real indicators of compromise (IPs, domains, hashes), customer/organizational identifiers, or other sensitive data. Simulation plans produced from extracted TTPs are for authorized detection-engineering/purple-team use, not for execution against systems without authorization.
