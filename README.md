#  Cybersecurity Automation Portfolio

A collection of Python tools for Detection, Monitoring, and Incident Response — built as part of a Cybersecurity Analyst portfolio.

##  Projects

### [01 — Log Analyzer & Brute Force Detector](./01_log_analyzer)
Parses SSH auth logs to detect brute force attacks and compromised accounts.
- Regex log parsing, pattern detection, JSON reporting

### [03 — File Integrity Monitor](./03_file_integrity_monitor)
Monitors sensitive files for unauthorized changes using SHA-256 hashing.
- Real-time monitoring, SQLite database, baseline comparison

### [04 — IP Reputation Checker](./04_ip_reputation_checker)
Checks IP addresses against AbuseIPDB API to identify malicious actors.
- API integration, risk scoring, automated reporting

##  How They Work Together
```
01 Log Analyzer        →    Discovers suspicious IPs
03 File Monitor        →    Detects unauthorized changes
04 IP Checker          →    Validates & scores suspicious IPs

       Detection    →    Monitoring    →    Response
```

##  Built With
- Python 3.8+
- Libraries: `requests`, `watchdog`, `sqlite3`, `hashlib`, `re`
- APIs: AbuseIPDB

##  Purpose
These projects demonstrate practical cybersecurity automation skills
including log analysis, file integrity monitoring, and threat intelligence
— core competencies for a Cybersecurity Analyst role.