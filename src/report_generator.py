"""
report_generator.py
--------------------
Turns detected alerts into a Markdown SOC incident report, formatted the
way an L1 analyst would hand it off to L2 / IR: severity, IOC, MITRE
mapping, and recommended next action.
"""

from datetime import datetime

SEVERITY_ACTIONS = {
    "Critical": "Escalate immediately to L2/Incident Response. Isolate affected host if possible.",
    "High": "Escalate to L2 for review within SLA. Block source IP at perimeter firewall.",
    "Medium": "Monitor for repeat activity. Add IP to watchlist.",
    "Low": "Log for trend analysis. No immediate action required.",
}


def generate_report(brute_force_alerts, compromise_alerts, output_path):
    all_alerts = brute_force_alerts + compromise_alerts
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = []
    lines.append("# SOC Incident Triage Report")
    lines.append(f"**Generated:** {generated_at}")
    lines.append(f"**Analyst Tier:** L1")
    lines.append(f"**Total Alerts:** {len(all_alerts)}\n")

    lines.append("## Summary")
    lines.append(f"- Brute-force attempts detected: {len(brute_force_alerts)}")
    lines.append(f"- Possible compromises detected: {len(compromise_alerts)}\n")

    lines.append("---\n")

    for i, alert in enumerate(sorted(all_alerts, key=lambda a: a["severity"] != "Critical"), 1):
        lines.append(f"## Alert {i}: {alert['type'].replace('_', ' ').title()}")
        lines.append(f"- **Severity:** {alert['severity']}")
        lines.append(f"- **Source IP:** {alert.get('source_ip', 'N/A')}")

        if alert["type"] == "BRUTE_FORCE_ATTEMPT":
            lines.append(f"- **Failed Attempts:** {alert['failed_count']}")
            lines.append(f"- **Usernames Targeted:** {', '.join(alert['usernames_tried'])}")
            lines.append(f"- **First Seen:** {alert['first_seen']}")
            lines.append(f"- **Last Seen:** {alert['last_seen']}")

        if alert["type"] == "POSSIBLE_COMPROMISE":
            lines.append(f"- **Compromised User:** {alert['compromised_user']}")
            lines.append(f"- **Login Time:** {alert['login_time']}")

        lines.append(f"- **MITRE ATT&CK:** {alert['mitre_attack']}")

        ti = alert.get("threat_intel")
        if ti:
            lines.append(f"- **Threat Intel Match:** {ti['reputation'].upper()} ({ti['source']}) — {ti['notes']}")
        else:
            lines.append("- **Threat Intel Match:** None found in local blocklist")

        lines.append(f"- **Recommended Action:** {SEVERITY_ACTIONS.get(alert['severity'], 'Review manually.')}")
        lines.append("")

    if not all_alerts:
        lines.append("No security-relevant events detected in this log window.")

    with open(output_path, "w") as f:
        f.write("\n".join(lines))

    return output_path
