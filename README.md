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

1. Run the scanner:
