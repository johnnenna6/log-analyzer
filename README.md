# Security Log Analyzer

Python tool for analyzing authentication logs and detecting brute force attacks.

## Features

- Parses `/var/log/secure` (Fedora/RHEL) for failed SSH login attempts
- Detects brute force patterns using sliding window analysis
- Configurable detection thresholds
- Groups attacks by user and source IP

## Requirements

- Python 3.7+
- Root access to read `/var/log/secure`

## Installation
```bash
git clone https://github.com/johnnenna6/log-analyzer.git
cd log-analyzer
```

## Usage

**Basic scan:**
```bash
sudo python3 log_analyzer.py
```

**Custom file and thresholds:**
```bash
sudo python3 log_analyzer.py -f /var/log/auth.log -t 3 -w 120
```

**Options:**
- `-f, --file` - Log file path (default: /var/log/secure)
- `-t, --threshold` - Failure threshold (default: 5)
- `-w, --window` - Time window in seconds (default: 60)

## Example Output
```
--------------------------------------------------------------
Scanning file for failed login attempts...
--------------------------------------------------------------

Total users with failed logins: 2
Total failed attempts: 18

============================================================
🚨 BRUTE FORCE ATTACKS DETECTED
============================================================

User: root
Source IP: 45.142.120.45
Attempts: 15 in 45.2 seconds
First attempt: 2026-01-28 14:22:10
Last attempt: 2026-01-28 14:22:55
```

## How It Works

Uses sliding window analysis to detect multiple failed authentication attempts from the same IP within a configurable time period. The tool:

1. Parses log files for failed password attempts
2. Groups attempts by username and source IP
3. Analyzes temporal patterns using sliding window
4. Alerts when threshold is exceeded within time window

## Use Cases

- Security monitoring and incident detection
- Compliance auditing (track unauthorized access attempts)
- Forensic analysis of authentication logs
- Baseline establishment for normal vs suspicious activity

## Legal Disclaimer

For authorized security monitoring only. Only analyze logs on systems you own or have explicit permission to monitor.

## Author

**John Nenna**
- [LinkedIn](https://www.linkedin.com/in/john-nenna-ba08a0268)
- [GitHub](https://github.com/johnnenna6)

Built while developing practical security operations skills and preparing for Security+ certification.
