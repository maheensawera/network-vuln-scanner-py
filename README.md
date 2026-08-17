This scans the target defined in `TARGET` and saves results to `scan_results.json`.

# Network Vulnerability Scanner & Reporter

A Python-based security tool that automates network reconnaissance, cross-references discovered services against the NVD (National Vulnerability Database), and generates professional PDF vulnerability reports.

## Overview

This tool was built as a hands-on cybersecurity project to simulate real-world penetration testing workflows — from initial reconnaissance to client-ready reporting.

## Features

- Automated port/service scanning using Nmap (via python-nmap)
- Service version detection
- CVE lookup against the NVD API for each discovered service
- Automatic PDF report generation with executive summary and risk-flagged findings

## Tech Stack

- Python 3
- Nmap
- python-nmap
- NVD REST API
- fpdf2 (PDF generation)

## Lab Environment

Tested in an isolated VirtualBox lab:
- Attacker machine: Kali Linux
- Target machine: Metasploitable2
- Network: Host-only (isolated from internet/production networks)

## Usage

Run the scanner:

    python3 scanner.py

This scans the target defined in TARGET and saves results to scan_results.json.

Generate the PDF report:

    python3 report_generator.py

This reads scan_results.json and produces vulnerability_report.pdf.

## Sample Findings

During testing against Metasploitable2, the tool successfully identified 23 open ports and 6 known CVEs, including a critical vsftpd 2.3.4 backdoor vulnerability (CVE-2011-2523).

## Disclaimer

This tool is for educational purposes and authorized security testing only. Only scan systems you own or have explicit permission to test.

## Author

Maheen — Aspiring Penetration Tester / Security Analyst
