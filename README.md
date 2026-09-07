# SOC Analyst L1 — Log Triage & Incident Reporting Toolkit

A Python-based toolkit that automates the first-pass triage workflow of a
Tier-1 SOC Analyst: parsing raw SSH authentication logs, detecting
brute-force attacks and possible account compromises, enriching alerts with
threat intelligence, and generating a Markdown incident report ready for
L2 escalation.

This project was built to demonstrate practical SOC L1 skills: log
analysis, alert triage, IOC enrichment, MITRE ATT&CK mapping, and incident
documentation.

## Why this project

Real L1 work is: watch the logs, spot the pattern, decide if it's noise or
a real incident, attach context, hand it off. This tool automates that
pipeline end-to-end on sample data so the workflow is fully reproducible.

## Features

- **Log parsing** — Regex-based parser for standard `sshd` auth.log format
- **Brute-force detection** — Flags any source IP with 5+ failed logins
  within a 5-minute window
- **Compromise detection** — Flags a *successful* login from an IP that
  just finished a brute-force burst (classic signs of a cracked credential)
- **Threat intel enrichment** — Cross-references flagged IPs against a
  local blocklist (swap in a real feed like AbuseIPDB or VirusTotal later)
- **MITRE ATT&CK mapping** — Each alert is tagged with its technique ID
  (e.g. `T1110 - Brute Force`, `T1078 - Valid Accounts`)
- **Auto-generated incident report** — Clean Markdown report with
  severity, IOCs, and recommended next action per alert

## Project structure

```
soc-analyst-l1-toolkit/
├── src/
│   ├── main.py              # CLI entry point / orchestrator
│   ├── log_analyzer.py      # Parsing + detection logic
│   └── report_generator.py  # Markdown report builder
├── sample_logs/
│   ├── auth.log             # Sample SSH auth log (includes a simulated attack)
│   └── threat_blocklist.csv # Sample threat intel feed
├── reports/                 # Generated incident reports land here
├── requirements.txt
├── LICENSE
└── README.md
```

## How it works

1. `parse_log_file()` reads `auth.log` and extracts structured events
   (timestamp, result, user, source IP) using regex.
2. `detect_brute_force()` groups failed logins by IP and flags any IP that
   crosses the failure threshold inside the time window.
3. `detect_compromise_after_burst()` checks whether any flagged IP then
   succeeded in logging in — the classic signature of a cracked account.
4. `enrich_alerts()` cross-checks every flagged IP against a local threat
   intel CSV and attaches reputation context.
5. `generate_report()` writes everything to a Markdown report with
   severity ratings and recommended actions, mirroring a real L1 → L2
   handoff document.

## Usage

```bash
git clone https://github.com/<your-username>/soc-analyst-l1-toolkit.git
cd soc-analyst-l1-toolkit
python3 src/main.py --log sample_logs/auth.log --blocklist sample_logs/threat_blocklist.csv
```

Output:

```
[*] Parsing log file: sample_logs/auth.log
[*] Parsed 25 auth events
[*] Running brute-force detection...
[*] 2 brute-force alert(s) found
[*] Checking for post-burst successful logins (possible compromise)...
[*] 1 possible compromise alert(s) found
[*] Loading threat intel blocklist: sample_logs/threat_blocklist.csv
[+] Incident report generated: reports/incident_report.md
```

The generated report lives at `reports/incident_report.md` — see
[`reports/incident_report.md`](reports/incident_report.md) for a real
sample output.

### Run it on your own logs

Point `--log` at any real (or sanitized) `auth.log` file from a Linux box:

```bash
python3 src/main.py --log /var/log/auth.log --blocklist sample_logs/threat_blocklist.csv
```

## Sample detection

The included `sample_logs/auth.log` contains a simulated attack: `185.220.101.4`
fires 10 failed logins against `root`, `admin`, `test`, and `ubuntu` within
seconds, then successfully logs in as `root`. The toolkit correctly flags
this as a `Critical` **possible compromise**, mapped to MITRE ATT&CK
`T1078 - Valid Accounts`, with a recommendation to escalate to IR
immediately.

## Roadmap / possible extensions

- [ ] Swap local blocklist for a live AbuseIPDB or VirusTotal API lookup
- [ ] Add Windows Event Log (EVTX) parsing support
- [ ] Add geolocation lookup for source IPs
- [ ] Export alerts to JSON for SIEM ingestion
- [ ] Add a Streamlit dashboard for visual triage

## Skills demonstrated

`Log Analysis` `SIEM Concepts` `Incident Triage` `Threat Intelligence`
`MITRE ATT&CK` `Python` `Regex` `Incident Reporting`

## License

MIT — see [LICENSE](LICENSE)
