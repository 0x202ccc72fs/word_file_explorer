import socket
import threading
import asyncio
from queue import Queue
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import track
import requests
import os
import random
import aiohttp
if os.name == "nt":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


# Initialize rich console
console = Console()

# Global variables
open_ports = []
subdomains_found = []
results_table = []
lock = threading.Lock()

# Subdomain wordlist (can be extended)
subdomain_wordlist = [
    "www", "mail", "ftp", "admin", "api", "test", "dev", "staging", "webmail", "store", "blog", "secure", "beta", "cloud"
]

# Expanded vulnerable ports dictionary with more services
vulnerable_ports = {
    21: {
        "desc": "FTP - Unencrypted file transfer.",
        "fix": "Use SFTP or FTPS for encrypted communication.",
        "attack": "Attempt brute force or sniff traffic using Wireshark.",
        "tool": "hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://{target}"
    },
    22: {
        "desc": "SSH - Weak credentials may be used.",
        "fix": "Use key-based authentication and disable root login.",
        "attack": "Try brute-forcing SSH with Hydra or CrackMapExec.",
        "tool": "hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{target}"
    },
    23: {
        "desc": "Telnet - Unencrypted communication protocol.",
        "fix": "Disable Telnet and use SSH instead.",
        "attack": "Perform brute-force login or sniff unencrypted traffic.",
        "tool": "hydra -l admin -P /usr/share/wordlists/rockyou.txt telnet://{target}"
    },
    25: {
        "desc": "SMTP - Open relay or weak authentication.",
        "fix": "Ensure SMTP authentication and disable open relay.",
        "attack": "Exploit misconfigured relay for spam delivery.",
        "tool": "nmap --script smtp-open-relay -p 25 {target}"
    },
    53: {
        "desc": "DNS - Open DNS resolver.",
        "fix": "Restrict DNS queries to internal systems.",
        "attack": "Perform DNS amplification attacks.",
        "tool": "dig @{target} ANY example.com"
    },
    80: {
        "desc": "HTTP - Unencrypted traffic.",
        "fix": "Use HTTPS and apply secure headers.",
        "attack": "Exploit outdated CMS or perform MITM attacks.",
        "tool": "nikto -h http://{target}"
    },
    110: {
        "desc": "POP3 - Unencrypted email retrieval.",
        "fix": "Use encrypted protocols like POP3S.",
        "attack": "Sniff email credentials over unencrypted connections.",
        "tool": "hydra -l user -P /usr/share/wordlists/rockyou.txt pop3://{target}"
    },
    123: {
        "desc": "NTP - Network Time Protocol vulnerable to amplification attacks.",
        "fix": "Configure NTP to restrict access.",
        "attack": "Exploit NTP amplification vulnerability.",
        "tool": "ntpdate -q {target}"
    },
    143: {
        "desc": "IMAP - Unencrypted email retrieval.",
        "fix": "Use encrypted protocols like IMAPS.",
        "attack": "Sniff IMAP traffic for credentials.",
        "tool": "hydra -l user -P /usr/share/wordlists/rockyou.txt imap://{target}"
    },
    161: {
        "desc": "SNMP - Exposed Simple Network Management Protocol.",
        "fix": "Restrict SNMP access and use strong community strings.",
        "attack": "Retrieve sensitive information using SNMP.",
        "tool": "onesixtyone -c public {target}"
    },
    389: {
        "desc": "LDAP - Exposed Lightweight Directory Access Protocol.",
        "fix": "Use LDAPS and restrict access.",
        "attack": "Retrieve sensitive directory information.",
        "tool": "ldapsearch -h {target} -x -b dc=example,dc=com"
    },
    443: {
        "desc": "HTTPS - SSL/TLS misconfiguration.",
        "fix": "Use modern SSL/TLS settings and verify certificates.",
        "attack": "Test for outdated protocols (e.g., SSLv3).",
        "tool": "sslscan {target}"
    },
    445: {
        "desc": "SMB - Exposed Server Message Block service.",
        "fix": "Disable SMBv1 and use SMBv3 with strong authentication.",
        "attack": "Exploit SMB vulnerabilities such as EternalBlue.",
        "tool": "smbclient -L {target}"
    },
    3306: {
        "desc": "MySQL - Database exposed to the internet.",
        "fix": "Restrict access to MySQL and enforce strong passwords.",
        "attack": "Brute-force credentials or exploit SQL vulnerabilities.",
        "tool": "hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://{target}"
    },
    3389: {
        "desc": "RDP - Remote Desktop exposed to the internet.",
        "fix": "Restrict access and enforce multi-factor authentication.",
        "attack": "Attempt brute force with specialized RDP tools.",
        "tool": "hydra -l admin -P /usr/share/wordlists/rockyou.txt rdp://{target}"
    },
    5900: {
        "desc": "VNC - Remote desktop protocol often without encryption.",
        "fix": "Use a VPN and strong authentication for VNC.",
        "attack": "Attempt brute force or sniff traffic for credentials.",
        "tool": "hydra -l admin -P /usr/share/wordlists/rockyou.txt vnc://{target}"
    },
    8080: {
        "desc": "HTTP Proxy - Open proxy server.",
        "fix": "Restrict access and disable unused proxy services.",
        "attack": "Exploit proxy misconfiguration for unauthorized access.",
        "tool": "nikto -h http://{target}:8080"
    }
}

# Function: Display header
def display_header():
    console.print("[bold magenta]" + "=" * 47 + "[/bold magenta]")
    console.print("[bold blue]███████╗ ██████╗  █████╗ ███╗   ██╗██╗███████╗[/bold blue]")
    console.print("[bold blue]██╔════╝██╔═══██╗██╔══██╗████╗  ██║██║██╔════╝[/bold blue]")
    console.print("[bold blue]███████╗██║   ██║███████║██╔██╗ ██║██║███████╗[/bold blue]")
    console.print("[bold blue]╚════██║██║   ██║██╔══██║██║╚██╗██║██║╚════██║[/bold blue]")
    console.print("[bold blue]███████║╚██████╔╝██║  ██║██║ ╚████║██║███████║[/bold blue]")
    console.print("[bold blue]╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚══════╝[/bold blue]")
    console.print("[bold yellow]               Made by Spynac[/bold yellow]")
    console.print("[bold magenta]" + "=" * 47 + "[/bold magenta]\n")

# Function: IP Geolocation with optimized response and aiohttp
def ip_geolocation(ip_address):
    console.print(f"\n[bold cyan]Geolocating IP: {ip_address}[/bold cyan]")
    try:
        async def fetch_geo():
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://ipapi.co/{ip_address}/json/") as response:
                    if response.status == 200:
                        data = await response.json()
                        console.print(f"[bold green]IP Geolocation Results:[/bold green]")
                        console.print(f"- [cyan]Country:[/cyan] {data.get('country_name', 'N/A')}")
                        console.print(f"- [cyan]Region:[/cyan] {data.get('region', 'N/A')}")
                        console.print(f"- [cyan]City:[/cyan] {data.get('city', 'N/A')}")
                        console.print(f"- [cyan]ISP:[/cyan] {data.get('org', 'N/A')}")
                        console.print(f"- [cyan]Latitude:[/cyan] {data.get('latitude', 'N/A')}")
                        console.print(f"- [cyan]Longitude:[/cyan] {data.get('longitude', 'N/A')}")
                    else:
                        console.print("[bold red]Failed to fetch geolocation data. Try again later.[/bold red]")
        asyncio.run(fetch_geo())
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")

# Function: Asynchronous Port Scanner
def async_port_scanner(target):
    async def scan_port(ip, port):
        try:
            reader, writer = await asyncio.open_connection(ip, port)
            with lock:
                open_ports.append(port)
                vulnerability = vulnerable_ports.get(port, {
                    "desc": "Unknown service.", "fix": "-", "attack": "-", "tool": "-"
                })
                results_table.append([
                    port, "Port", vulnerability["desc"], vulnerability["fix"], vulnerability["attack"], vulnerability["tool"]
                ])
                console.print(f"[green]Port {port} is open[/green]")
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    async def run_scanner():
        tasks = []
        ip_address = socket.gethostbyname(target)
        console.print(f"[bold cyan]Target IP Address:[/bold cyan] {ip_address}")
        for port in range(1, 1025):
            tasks.append(scan_port(ip_address, port))
        await asyncio.gather(*tasks)

    start_time = datetime.now()
    console.print(f"\n[bold green]Port Scan started at {start_time}[/bold green]\n")
    asyncio.run(run_scanner())
    end_time = datetime.now()
    duration = end_time - start_time
    console.print(f"\n[bold green]Port Scan completed in {duration}[/bold green]")

    display_results()

# Function: Subdomain Scanner with aiohttp
def subdomain_scanner(domain):
    async def fetch_subdomain(subdomain):
        url = f"http://{subdomain}.{domain}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=3) as response:
                    if response.status == 200:
                        with lock:
                            subdomains_found.append(url)
                            console.print(f"[green]Discovered subdomain: {url}[/green]")
        except Exception:
            pass

    async def run_scanner():
        tasks = []
        for subdomain in subdomain_wordlist:
            tasks.append(fetch_subdomain(subdomain))
        await asyncio.gather(*tasks)

    console.print(f"\n[bold cyan]Starting subdomain scan for: {domain}[/bold cyan]")
    start_time = datetime.now()
    asyncio.run(run_scanner())
    end_time = datetime.now()
    duration = end_time - start_time
    console.print(f"\n[bold green]Subdomain Scan completed in {duration}[/bold green]")

    if subdomains_found:
        console.print("\n[bold magenta]Discovered Subdomains:[/bold magenta]")
        for subdomain in subdomains_found:
            console.print(f"- {subdomain}")
    else:
        console.print("[bold red]No subdomains found.[/bold red]")

# Function: Display results in a table
def display_results():
    if results_table:
        table = Table(title="Scan Results", style="bold magenta")
        table.add_column("Port", justify="left", style="cyan")
        table.add_column("Type", justify="center", style="green")
        table.add_column("Details", justify="left", style="yellow")
        table.add_column("Fix", justify="left", style="red")
        table.add_column("Attack", justify="left", style="purple")
        table.add_column("Tool", justify="left", style="blue")
        for row in results_table:
            table.add_row(*[str(item) for item in row])
        console.print(table)
    else:
        console.print("[bold red]No results to display.[/bold red]")

# Function: Execute attacks from menu
def execute_attacks():
    if results_table:
        console.print("\n[bold cyan]Attack Menu:[/bold cyan]")
        for i, result in enumerate(results_table):
            port, _, details, _, attack, tool = result
            console.print(f"[{i+1}] Port {port}: {details}")
        choice = console.input("\n[bold yellow]Enter the number of the port to attack (or 'q' to quit): [/bold yellow]")
        if choice.isdigit() and 1 <= int(choice) <= len(results_table):
            selected = results_table[int(choice)-1]
            command = selected[5].format(target="127.0.0.1")  # Replace with actual target
            console.print(f"[bold cyan]Executing: {command}[/bold cyan]")
            os.system(command)
    else:
        console.print("[bold red]No vulnerabilities to attack.[/bold red]")

# Function: Main menu
def main_menu():
    display_header()
    while True:
        console.print("\n[bold cyan]Main Menu:[/bold cyan]")
        console.print("[1] Port Scanner")
        console.print("[2] Subdomain Scanner")
        console.print("[3] IP Geolocation")
        console.print("[4] Execute Attacks")
        console.print("[5] Quit")
        choice = console.input("\n[bold yellow]Enter your choice (1-5): [/bold yellow]")

        if choice == "1":
            target = console.input("[bold yellow]Enter the target domain or IP (e.g., 'example.com'): [/bold yellow]")
            async_port_scanner(target)
        elif choice == "2":
            target = console.input("[bold yellow]Enter the target domain (e.g., 'example.com'): [/bold yellow]")
            subdomain_scanner(target)
        elif choice == "3":
            ip_address = console.input("[bold yellow]Enter the IP address to geolocate: [/bold yellow]")
            ip_geolocation(ip_address)
        elif choice == "4":
            execute_attacks()
        elif choice == "5":
            console.print("[bold green]Exiting Scanify Ultimate. Goodbye![/bold green]")
            break
        else:
            console.print("[bold red]Invalid choice. Please try again.[/bold red]")

if __name__ == "__main__":
    main_menu()
