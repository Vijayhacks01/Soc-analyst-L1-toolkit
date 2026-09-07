# SOC Incident Triage Report
**Generated:** 2026-09-07 06:15:34
**Analyst Tier:** L1
**Total Alerts:** 3

## Summary
- Brute-force attempts detected: 2
- Possible compromises detected: 1

---

## Alert 1: Possible Compromise
- **Severity:** Critical
- **Source IP:** 185.220.101.4
- **Compromised User:** root
- **Login Time:** 2026-09-07 02:04:05
- **MITRE ATT&CK:** T1078 - Valid Accounts (post brute-force)
- **Threat Intel Match:** MALICIOUS (internal_watchlist) — Known Tor exit node used in prior brute-force campaigns
- **Recommended Action:** Escalate immediately to L2/Incident Response. Isolate affected host if possible.

## Alert 2: Brute Force Attempt
- **Severity:** High
- **Source IP:** 185.220.101.4
- **Failed Attempts:** 10
- **Usernames Targeted:** admin, root, test, ubuntu
- **First Seen:** 2026-09-07 02:03:44
- **Last Seen:** 2026-09-07 02:04:02
- **MITRE ATT&CK:** T1110 - Brute Force
- **Threat Intel Match:** MALICIOUS (internal_watchlist) — Known Tor exit node used in prior brute-force campaigns
- **Recommended Action:** Escalate to L2 for review within SLA. Block source IP at perimeter firewall.

## Alert 3: Brute Force Attempt
- **Severity:** High
- **Source IP:** 45.155.205.87
- **Failed Attempts:** 6
- **Usernames Targeted:** oracle, postgres
- **First Seen:** 2026-09-07 06:11:12
- **Last Seen:** 2026-09-07 06:11:22
- **MITRE ATT&CK:** T1110 - Brute Force
- **Threat Intel Match:** MALICIOUS (internal_watchlist) — Flagged in abuse.ch feed for SSH scanning
- **Recommended Action:** Escalate to L2 for review within SLA. Block source IP at perimeter firewall.
