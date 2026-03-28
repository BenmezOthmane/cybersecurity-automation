# Log Analyzer & Brute Force Detector

## Description
Python tool that parses SSH auth logs to detect brute force attacks,
suspicious IPs, and compromised accounts.

## Features
- Detects brute force attacks based on failed login threshold
- Identifies most targeted usernames
- Flags IPs that brute forced AND logged in successfully
- Generates structured JSON report

## Usage
```bash
# Basic
python log_analyzer.py

# Custom log file
python log_analyzer.py --log /var/log/auth.log

# Custom threshold
python log_analyzer.py --threshold 10
```

## Skills Demonstrated
- Log parsing with Regex
- Pattern detection & cross-referencing
- CLI tool design with argparse
- JSON report generation