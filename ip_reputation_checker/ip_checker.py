import requests
import json
import time
import argparse
from datetime import datetime
from pathlib import Path

# ──────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────
ABUSEIPDB_KEY = "059c1d730a27abf83196fe2beab80261f9e46ec3f1c810d4c59563323ff47036a25e232b79833283"

OUTPUT_DIR  = Path("reports")
OUTPUT_DIR.mkdir(exist_ok=True)

# ──────────────────────────────────────────
# ABUSEIPDB
# ──────────────────────────────────────────
def check_abuseipdb(ip):
    """Check IP reputation via AbuseIPDB API."""
    url     = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_KEY
    }
    params = {
        "ipAddress":    ip,
        "maxAgeInDays": 90
    }

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "ip":             ip,
            "abuse_score":    data.get("abuseConfidenceScore", 0),
            "total_reports":  data.get("totalReports", 0),
            "country":        data.get("countryCode", "N/A"),
            "isp":            data.get("isp", "N/A"),
            "last_reported":  data.get("lastReportedAt", "Never"),
        }
    except requests.RequestException as e:
        print(f"  [ERROR] {ip} — {e}")
        return None


# ──────────────────────────────────────────
# RISK LEVEL
# ──────────────────────────────────────────
def get_risk_level(score):
    """Determine risk level based on abuse score."""
    if score == 0:
        return "CLEAN",  "🟢"
    elif score < 25:
        return "LOW",    "🔵"
    elif score < 50:
        return "MEDIUM", "🟡"
    elif score < 75:
        return "HIGH",   "🟠"
    else:
        return "CRITICAL","🔴"


# ──────────────────────────────────────────
# PRINT REPORT
# ──────────────────────────────────────────
def print_results(results):
    """Print formatted results to terminal."""
    print("\n" + "═" * 65)
    print("           🔍 IP REPUTATION REPORT")
    print("═" * 65)
    print(f"  {'IP':<18} {'SCORE':<8} {'RISK':<10} {'REPORTS':<10} {'COUNTRY'}")
    print("─" * 65)

    for r in results:
        if not r:
            continue
        risk, icon = get_risk_level(r["abuse_score"])
        print(
            f"  {r['ip']:<18} "
            f"{r['abuse_score']:<8} "
            f"{icon} {risk:<8} "
            f"{r['total_reports']:<10} "
            f"{r['country']}"
        )

    print("═" * 65)

    # Summary
    clean    = sum(1 for r in results if r and r["abuse_score"] == 0)
    critical = sum(1 for r in results if r and r["abuse_score"] >= 75)
    print(f"\n  ✅ Clean: {clean}  |  🔴 Critical: {critical}  |  Total: {len(results)}")
    print()


# ──────────────────────────────────────────
# SAVE REPORT
# ──────────────────────────────────────────
def save_report(results):
    """Save results to JSON file."""
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = OUTPUT_DIR / f"report_{timestamp}.json"

    report = {
        "generated_at": datetime.now().isoformat(),
        "total_ips":    len(results),
        "results":      results
    }

    with open(output_path, "w") as f:
        json.dump(report, f, indent=4)

    print(f"  [✓] Report saved: {output_path}")


# ──────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="IP Reputation Checker")
    parser.add_argument("--file", default="ips.txt", help="File containing IPs")
    args = parser.parse_args()

    # Read IPs from file
    ip_file = Path(args.file)
    if not ip_file.exists():
        print(f"[ERROR] File not found: {args.file}")
        return

    ips = [line.strip() for line in ip_file.read_text().splitlines() if line.strip()]
    print(f"\n[*] Checking {len(ips)} IPs via AbuseIPDB...")
    print(f"[*] Started at: {datetime.now().strftime('%H:%M:%S')}\n")

    results = []
    for i, ip in enumerate(ips, 1):
        print(f"  [{i}/{len(ips)}] Checking {ip}...", end=" ")
        result = check_abuseipdb(ip)
        if result:
            risk, icon = get_risk_level(result["abuse_score"])
            print(f"{icon} {risk}")
            results.append(result)
        time.sleep(1)  # Avoid rate limiting

    print_results(results)
    save_report(results)


if __name__ == "__main__":
    main()