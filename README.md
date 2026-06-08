# osint-tool

A modular OSINT automation tool that queries multiple threat intelligence sources for a given IP address.

## Data sources
- VirusTotal — malicious detection count across 70+ antivirus engines
- AbuseIPDB — abuse confidence score and report history
- Shodan — open ports, services, and known CVEs

## Usage
```bash
python recon.py --target 8.8.8.8 --type ip
```

## Setup
1. Clone the repo
2. `pip install -r requirements.txt`
3. Create a `.env` file with your API keys:

VT_API_KEY=your_key
ABUSE_API_KEY=your_key
SHODAN_API_KEY=your_key

## Why I built this
Practice building modular Python tooling for threat intel workflows.
Relevant to roles in DFIR, threat intelligence, and SOC analysis.