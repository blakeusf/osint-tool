import argparse
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from modules import virustotal, abuseipdb, shodan

load_dotenv()
console = Console()

def run(target, type):
    console.print(f"\n[bold]Recon report — {target}[/bold]\n")

    if type == "ip":
        vt = virustotal.check_ip(target)
        ab = abuseipdb.check_ip(target)
        sh = shodan.check_ip(target)

        t = Table(show_header=False, box=None, padding=(0,2))
        t.add_column(style="dim", width=20)
        t.add_column()
        t.add_row("[bold cyan]VirusTotal[/]", "")
        t.add_row("  Malicious", str(vt.get("malicious", "N/A")))
        t.add_row("  Suspicious", str(vt.get("suspicious", "N/A")))
        t.add_row("  Country", vt.get("country", "N/A"))
        t.add_row("  Owner", vt.get("owner", "N/A"))
        t.add_row("", "")
        t.add_row("[bold cyan]AbuseIPDB[/]", "")
        t.add_row("  Abuse score", f"{ab.get('abuse_score', 'N/A')}%")
        t.add_row("  Reports", str(ab.get("total_reports", "N/A")))
        t.add_row("  Last report", ab.get("last_reported", "N/A"))
        t.add_row("", "")
        t.add_row("[bold cyan]Shodan[/]", "")
        t.add_row("  Open ports", str(sh.get("open_ports", "N/A")))
        t.add_row("  Org", sh.get("org", "N/A"))
        t.add_row("  OS", sh.get("os", "N/A"))
        t.add_row("  CVEs", ", ".join(sh.get("vulns", [])) or "None")

        console.print(t)
    else:
        console.print("[red]Only --type ip is supported in this MVP[/]")

parser = argparse.ArgumentParser(description="OSINT recon tool")
parser.add_argument("--target", required=True, help="IP, domain, or email")
parser.add_argument("--type", required=True, choices=["ip","domain","email"])
args = parser.parse_args()
run(args.target, args.type)