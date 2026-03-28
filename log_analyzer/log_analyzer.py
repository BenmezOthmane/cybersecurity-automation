import re
import json
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# ──────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────
DEFAULT_THRESHOLD = 5
DEFAULT_LOG_FILE  = "sample_auth.log"
REPORT_FILE       = "report.json"

PATTERNS = {
    "failed_logins": re.compile(
        r"Failed password for (?:invalid user )?(\w+) from ([\d.]+) port \d+"
    ),
    "successful_logins": re.compile(
        r"Accepted password for (\w+) from ([\d.]+) port \d+"
    ),
    "invalid_users": re.compile(
        r"Invalid user (\w+) from ([\d.]+)"
    ),
}

# ──────────────────────────────────────────
# FUNCTIONS
# ──────────────────────────────────────────
def parse_log_file(filepath):
    path = Path(filepath)
    if not path.exists():
        print(f"[ERROR] File not found: {filepath}")
        return {}

    print(f"[*] Parsing: {filepath}")
    events = {
        "failed_logins":     [],
        "successful_logins": [],
        "invalid_users":     [],
    }

    total = 0
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            total += 1
            for event_type, pattern in PATTERNS.items():
                match = pattern.search(line)
                if match:
                    events[event_type].append((match.group(1), match.group(2)))

    print(f"[*] Lines processed  : {total}")
    print(f"[*] Failed logins    : {len(events['failed_logins'])}")
    print(f"[*] Successful logins: {len(events['successful_logins'])}")
    return events


def detect_brute_force(events, threshold):
    ip_count = defaultdict(int)
    for user, ip in events.get("failed_logins", []):
        ip_count[ip] += 1
    for user, ip in events.get("invalid_users", []):
        ip_count[ip] += 1
    return {ip: c for ip, c in ip_count.items() if c >= threshold}


def get_targeted_users(events):
    users = defaultdict(int)
    for user, ip in events.get("failed_logins", []):
        users[user] += 1
    for user, ip in events.get("invalid_users", []):
        users[user] += 1
    return dict(sorted(users.items(), key=lambda x: x[1], reverse=True))


def find_compromised(suspicious_ips, events):
    successful = [ip for _, ip in events.get("successful_logins", [])]
    return [ip for ip in suspicious_ips if ip in successful]


def print_report(suspicious_ips, targeted_users, compromised, threshold):
    print("\n" + "═" * 50)
    print("        🔍 SECURITY ANALYSIS REPORT")
    print("═" * 50)

    print(f"\n[!] BRUTE FORCE IPs (threshold: {threshold})")
    print("-" * 50)
    if suspicious_ips:
        for ip, c in sorted(suspicious_ips.items(), key=lambda x: x[1], reverse=True):
            print(f"  {ip:<20} {c:>3} attempts  {'█' * min(c, 30)}")
    else:
        print("  ✓ None detected")

    print(f"\n[!] TARGETED USERNAMES")
    print("-" * 50)
    for user, c in list(targeted_users.items())[:8]:
        print(f"  {user:<20} {c:>3} attempts")

    print(f"\n[!!!] POSSIBLE SUCCESSFUL ATTACKS")
    print("-" * 50)
    if compromised:
        for ip in compromised:
            print(f"  ⚠️  {ip} — brute forced AND logged in!")
    else:
        print("  ✓ None detected")

    print("\n" + "═" * 50)


def save_report(events, suspicious_ips, targeted_users, compromised, output):
    report = {
        "generated_at": datetime.now().isoformat(),
        "summary": {
            "failed_logins":     len(events.get("failed_logins", [])),
            "successful_logins": len(events.get("successful_logins", [])),
            "suspicious_ips":    len(suspicious_ips),
            "compromised_ips":   len(compromised),
        },
        "suspicious_ips":  suspicious_ips,
        "targeted_users":  targeted_users,
        "compromised_ips": compromised,
    }
    with open(output, "w") as f:
        json.dump(report, f, indent=4)
    print(f"\n[✓] Report saved: {output}")


# ──────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Log Analyzer & Brute Force Detector")
    parser.add_argument("--log",       default=DEFAULT_LOG_FILE)
    parser.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD)
    parser.add_argument("--output",    default=REPORT_FILE)
    args = parser.parse_args()

    print("\n[*] Log Analyzer started")
    print(f"[*] Threshold: {args.threshold} attempts\n")

    events      = parse_log_file(args.log)
    if not events: return

    suspicious  = detect_brute_force(events, args.threshold)
    targeted    = get_targeted_users(events)
    compromised = find_compromised(suspicious, events)

    print_report(suspicious, targeted, compromised, args.threshold)
    save_report(events, suspicious, targeted, compromised, args.output)


if __name__ == "__main__":
    main()