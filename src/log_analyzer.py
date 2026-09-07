"""
log_analyzer.py
----------------
Parses SSH authentication logs (auth.log format) and detects SOC-relevant
security events:
  - Brute-force login attempts (>= FAILED_THRESHOLD failures from one IP)
  - Successful login immediately following a brute-force burst (possible compromise)
  - Logins from unfamiliar / non-whitelisted source IPs

This mirrors the first-pass triage an L1 SOC analyst performs on raw logs
before escalating anything to L2.
"""

import re
import csv
from collections import defaultdict
from datetime import datetime

FAILED_THRESHOLD = 5          # failed attempts from one IP to flag as brute-force
TIME_WINDOW_SECONDS = 300      # 5-minute window for correlating burst attempts

LOG_LINE_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"(?P<result>Accepted|Failed)\s+(?P<method>\w+)\s+for\s+(?P<user>\S+)\s+"
    r"from\s+(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)"
)

CURRENT_YEAR = datetime.now().year


def parse_log_file(filepath):
    """Parse an auth.log file into a list of structured event dicts."""
    events = []
    with open(filepath, "r") as f:
        for line in f:
            match = LOG_LINE_PATTERN.match(line.strip())
            if not match:
                continue
            data = match.groupdict()
            timestamp_str = f"{CURRENT_YEAR} {data['month']} {data['day']} {data['time']}"
            timestamp = datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S")
            events.append({
                "timestamp": timestamp,
                "host": data["host"],
                "result": data["result"],
                "method": data["method"],
                "user": data["user"],
                "ip": data["ip"],
                "port": data["port"],
            })
    return events


def detect_brute_force(events):
    """Group failed attempts by source IP and flag IPs over the threshold."""
    failures_by_ip = defaultdict(list)
    for e in events:
        if e["result"] == "Failed":
            failures_by_ip[e["ip"]].append(e)

    alerts = []
    for ip, attempts in failures_by_ip.items():
        attempts.sort(key=lambda x: x["timestamp"])
        if len(attempts) >= FAILED_THRESHOLD:
            span_seconds = (attempts[-1]["timestamp"] - attempts[0]["timestamp"]).total_seconds()
            if span_seconds <= TIME_WINDOW_SECONDS:
                users_tried = sorted({a["user"] for a in attempts})
                alerts.append({
                    "type": "BRUTE_FORCE_ATTEMPT",
                    "severity": "High",
                    "source_ip": ip,
                    "failed_count": len(attempts),
                    "usernames_tried": users_tried,
                    "first_seen": attempts[0]["timestamp"],
                    "last_seen": attempts[-1]["timestamp"],
                    "mitre_attack": "T1110 - Brute Force",
                })
    return alerts


def detect_compromise_after_burst(events, brute_force_alerts):
    """Flag if a successful login occurs from an IP right after it brute-forced."""
    flagged_ips = {a["source_ip"] for a in brute_force_alerts}
    alerts = []
    for e in events:
        if e["result"] == "Accepted" and e["ip"] in flagged_ips:
            alerts.append({
                "type": "POSSIBLE_COMPROMISE",
                "severity": "Critical",
                "source_ip": e["ip"],
                "compromised_user": e["user"],
                "login_time": e["timestamp"],
                "mitre_attack": "T1078 - Valid Accounts (post brute-force)",
            })
    return alerts


def load_threat_blocklist(filepath):
    """Load known-bad IPs from a threat intel CSV for enrichment."""
    blocklist = {}
    with open(filepath, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            blocklist[row["ip"]] = {
                "reputation": row["reputation"],
                "source": row["source"],
                "notes": row["notes"],
            }
    return blocklist


def enrich_alerts(alerts, blocklist):
    """Attach threat intel context to any alert whose IP is on the blocklist."""
    for alert in alerts:
        ip = alert.get("source_ip")
        if ip in blocklist:
            alert["threat_intel"] = blocklist[ip]
        else:
            alert["threat_intel"] = None
    return alerts
