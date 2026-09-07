"""
main.py
-------
Entry point for the SOC Analyst L1 Log Triage Toolkit.

Usage:
    python src/main.py --log sample_logs/auth.log --blocklist sample_logs/threat_blocklist.csv

This simulates the L1 workflow:
    1. Ingest raw SSH auth logs
    2. Detect brute-force attempts and post-burst logins (possible compromise)
    3. Enrich flagged IPs against a threat intel blocklist
    4. Generate a Markdown incident report for L2 handoff
"""

import argparse
import os
import sys

from log_analyzer import (
    parse_log_file,
    detect_brute_force,
    detect_compromise_after_burst,
    load_threat_blocklist,
    enrich_alerts,
)
from report_generator import generate_report


def main():
    parser = argparse.ArgumentParser(description="SOC Analyst L1 Log Triage Toolkit")
    parser.add_argument("--log", required=True, help="Path to auth.log file")
    parser.add_argument("--blocklist", required=True, help="Path to threat intel blocklist CSV")
    parser.add_argument("--out", default="reports/incident_report.md", help="Output report path")
    args = parser.parse_args()

    if not os.path.exists(args.log):
        print(f"[!] Log file not found: {args.log}")
        sys.exit(1)

    print(f"[*] Parsing log file: {args.log}")
    events = parse_log_file(args.log)
    print(f"[*] Parsed {len(events)} auth events")

    print("[*] Running brute-force detection...")
    brute_force_alerts = detect_brute_force(events)
    print(f"[*] {len(brute_force_alerts)} brute-force alert(s) found")

    print("[*] Checking for post-burst successful logins (possible compromise)...")
    compromise_alerts = detect_compromise_after_burst(events, brute_force_alerts)
    print(f"[*] {len(compromise_alerts)} possible compromise alert(s) found")

    print(f"[*] Loading threat intel blocklist: {args.blocklist}")
    blocklist = load_threat_blocklist(args.blocklist)

    brute_force_alerts = enrich_alerts(brute_force_alerts, blocklist)
    compromise_alerts = enrich_alerts(compromise_alerts, blocklist)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    report_path = generate_report(brute_force_alerts, compromise_alerts, args.out)
    print(f"[+] Incident report generated: {report_path}")


if __name__ == "__main__":
    main()
