import requests
import whois
from rich.console import Console
from rich.table import Table
import asyncio
import aiohttp
from ipwhois import IPWhois
import json
import time

# Initialize rich console
console = Console()

# Function: Display header
def display_header():
    console.print("[bold magenta]" + "=" * 80 + "[/bold magenta]")
    console.print("[bold blue] ███████╗███████╗ █████╗ ██████╗ [/bold blue]")
    console.print("[bold blue] ██╔════╝██╔════╝██╔══██╗██╔══██╗[/bold blue]")
    console.print("[bold blue] █████╗  █████╗  ███████║██████╔╝[/bold blue]")
    console.print("[bold blue] ██╔══╝  ██╔══╝  ██╔══██║██╔═══╝ [/bold blue]")
    console.print("[bold blue] ███████╗██║     ██║  ██║██║     [/bold blue]")
    console.print("[bold blue] ╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝     [/bold blue]")
    console.print("[bold yellow]                      MADE BY SPYNAC[/bold yellow]")
    console.print("[bold magenta]" + "=" * 80 + "[/bold magenta]\n")

# Function: Social Media Profiler
async def social_media_profiler(username):
    platforms = {
        "Twitter": f"https://twitter.com/{username}",
        "Instagram": f"https://instagram.com/{username}",
        "LinkedIn": f"https://www.linkedin.com/in/{username}",
        "GitHub": f"https://github.com/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "Facebook": f"https://facebook.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}"
    }
    console.print(f"\n[bold cyan]Checking social media profiles for: {username}[/bold cyan]")
    async with aiohttp.ClientSession() as session:
        tasks = [asyncio.create_task(check_profile(session, platform, url)) for platform, url in platforms.items()]
        await asyncio.gather(*tasks)

async def check_profile(session, platform, url):
    try:
        async with session.get(url, allow_redirects=True) as response:
            if response.status == 200:
                console.print(f"[bold green]{platform} profile found:[/bold green] {url}")
                # Optional: Scrape public data if available
                if platform in ["Twitter", "Instagram"]:
                    page_content = await response.text()
                    console.print(f"[cyan]Parsing data (if public):[/cyan] Limited by platform restrictions.")
            else:
                console.print(f"[bold yellow]{platform} profile not found.[/bold yellow]")
    except Exception as e:
        console.print(f"[bold red]Error checking {platform}:[/bold red] {e}")

# Function: Email Breach Checker
async def email_breach_checker(email):
    console.print(f"\n[bold cyan]Checking breaches for: {email}[/bold cyan]")
    potential_sources = [
        f"https://haveibeenpwned.com/unverified-email/{email}",
        f"https://leakcheck.net/api/check/{email}",
        f"https://hunter.io/email-finder?search={email}"
    ]
    async with aiohttp.ClientSession() as session:
        tasks = [asyncio.create_task(fetch_email_breach(session, url)) for url in potential_sources]
        await asyncio.gather(*tasks)

async def fetch_email_breach(session, url):
    try:
        async with session.get(url, allow_redirects=True) as response:
            if response.status == 200:
                data = await response.text()
                console.print(f"[bold green]Data fetched from {url}:[/bold green]")
                console.print(data)
            else:
                console.print(f"[bold yellow]No data found at {url}.[/bold yellow]")
    except Exception as e:
        console.print(f"[bold red]Error fetching data from {url}:[/bold red] {e}")

# Function: Geo IP Lookup
def geo_ip_lookup(ip_address):
    console.print(f"\n[bold cyan]Performing Geo IP lookup for: {ip_address}[/bold cyan]")
    try:
        obj = IPWhois(ip_address)
        results = obj.lookup_rdap(asn_methods=["whois", "http"])
        table = Table(title="Geo IP Information", show_lines=True)
        table.add_column("Field", justify="right", style="cyan", no_wrap=True)
        table.add_column("Value", style="green")
        table.add_row("IP Address", ip_address)
        table.add_row("Country", results.get("asn_country_code", "Unknown"))
        table.add_row("ASN", results.get("asn", "Unknown"))
        table.add_row("ASN Description", results.get("asn_description", "Unknown"))
        table.add_row("Network", results.get("network", {}).get("handle", "Unknown"))
        table.add_row("Abuse Contact", results.get("objects", {}).get("contact", "Unknown"))
        console.print(table)
    except Exception as e:
        console.print(f"[bold red]Error during Geo IP lookup:[/bold red] {e}")

# Enhanced: Logging and Export Functionality
def export_results(filename, data):
    try:
        with open(filename, 'w') as file:
            json.dump(data, file, indent=4)
        console.print(f"[bold green]Results successfully exported to {filename}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Error exporting results:[/bold red] {e}")

# Main Menu
def main_menu():
    display_header()
    while True:
        console.print("\n[bold cyan]Main Menu:[/bold cyan]")
        console.print("[1] Social Media Profiler")
        console.print("[2] Email Breach Checker")
        console.print("[3] Geo IP Lookup")
        console.print("[4] Quit")
        choice = console.input("\n[bold yellow]Enter your choice (1-4): [/bold yellow]")

        if choice == "1":
            username = console.input("[bold yellow]Enter the username to search: [/bold yellow]")
            asyncio.run(social_media_profiler(username))
        elif choice == "2":
            email = console.input("[bold yellow]Enter the email to check for breaches: [/bold yellow]")
            asyncio.run(email_breach_checker(email))
        elif choice == "3":
            ip_address = console.input("[bold yellow]Enter the IP address for Geo IP lookup: [/bold yellow]")
            geo_ip_lookup(ip_address)
        elif choice == "4":
            console.print("[bold green]Exiting OSINT Ultimate. Goodbye![/bold green]")
            break
        else:
            console.print("[bold red]Invalid choice. Please try again.[/bold red]")

if __name__ == "__main__":
    main_menu()
