# core.py
import asyncio
import aiohttp
import aiodns
import socket
import ssl
import logging
import json
import sys
import time
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn
from rich.panel import Panel
from rich.logging import RichHandler
from dataclasses import dataclass
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor
import shodan
import requests
import dns.resolver
import nmap
from censys.search import CensysHosts

# Advanced Configuration
CONFIG = {
    'timeout': 5,
    'max_concurrent': 100,
    'rate_limit': 50,
    'ports': {
        'quick': [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080],
        'full': range(1, 65536),
        'top': [80,443,22,21,25,3389,110,445,139,143,53,135,3306,8080,1723,111,995,993,5900,1025]
    },
    'apis': {
        'shodan_key': 'YOUR_SHODAN_KEY',
        'censys_id': 'YOUR_CENSYS_ID',
        'censys_secret': 'YOUR_CENSYS_SECRET'
    }
}

class NextGenScanner:
    def __init__(self):
        self.console = Console()
        self.setup_logging()
        self.session = aiohttp.ClientSession()
        self.dns_resolver = aiodns.DNSResolver()
        self.shodan_api = shodan.Shodan(CONFIG['apis']['shodan_key'])
        self.censys_api = CensysHosts(
            api_id=CONFIG['apis']['censys_id'],
            api_secret=CONFIG['apis']['censys_secret']
        )
        self.nmap = nmap.PortScanner()
        self.results = {}
        self.start_time = None

    def setup_logging(self):
        logging.basicConfig(
            level="INFO",
            format="%(message)s",
            datefmt="[%X]",
            handlers=[RichHandler(rich_tracebacks=True)]
        )
        self.logger = logging.getLogger("rich")

    async def enhanced_port_scan(self, target: str) -> Dict:
        """Advanced port scanning with service detection and vulnerability analysis"""
        ports = []
        vulns = []
        
        # Parallel scanning with nmap and async socket checks
        async def scan_port(port):
            try:
                future = asyncio.get_event_loop().run_in_executor(
                    None, 
                    self.nmap.scan,
                    target,
                    str(port),
                    '-sV -sC --version-intensity 5'
                )
                results = await asyncio.wait_for(future, timeout=CONFIG['timeout'])
                
                if results['scan'][target]['tcp'][port]['state'] == 'open':
                    service = results['scan'][target]['tcp'][port]['name']
                    version = results['scan'][target]['tcp'][port]['version']
                    
                    # Check for known vulnerabilities
                    vulns.extend(await self.check_vulnerabilities(service, version))
                    
                    ports.append({
                        'port': port,
                        'service': service,
                        'version': version,
                        'state': 'open'
                    })
                    
            except Exception as e:
                self.logger.debug(f"Error scanning port {port}: {str(e)}")

        tasks = []
        for port in CONFIG['ports']['top']:  # Can be changed to 'full' for complete scan
            tasks.append(scan_port(port))

        await asyncio.gather(*tasks)
        return {'ports': ports, 'vulnerabilities': vulns}

    async def advanced_geo_ip(self, target: str) -> Dict:
        """Enhanced IP geolocation with multiple data sources"""
        geo_data = {}
        
        # Multiple API sources for redundancy and validation
        apis = [
            ('ipapi', f'https://ipapi.co/{target}/json/'),
            ('ipwhois', f'http://ipwhois.app/json/{target}'),
            ('ipstack', f'http://api.ipstack.com/{target}?access_key=YOUR_IPSTACK_KEY')
        ]
        
        for name, url in apis:
            try:
                async with self.session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        geo_data[name] = self.process_geo_data(name, data)
            except Exception as e:
                self.logger.error(f"Error with {name}: {str(e)}")
                
        # Additional threat intelligence
        try:
            shodan_data = await asyncio.get_event_loop().run_in_executor(
                None, self.shodan_api.host, target
            )
            geo_data['shodan'] = {
                'tags': shodan_data.get('tags', []),
                'vulns': shodan_data.get('vulns', []),
                'ports': shodan_data.get('ports', []),
                'hostnames': shodan_data.get('hostnames', [])
            }
        except Exception:
            pass
            
        return {'geo_data': geo_data}

    async def enhanced_subdomain_scan(self, domain: str) -> Dict:
        """Advanced subdomain enumeration"""
        subdomains = set()
        
        # Multiple enumeration techniques
        async def dns_brute_force():
            wordlist = self.load_wordlist('subdomains.txt')
            for word in wordlist:
                subdomain = f"{word}.{domain}"
                try:
                    answers = await self.dns_resolver.query(subdomain, 'A')
                    if answers:
                        subdomains.add(subdomain)
                except Exception:
                    continue

        async def certificate_search():
            try:
                # Search crt.sh database
                url = f"https://crt.sh/?q=%.{domain}&output=json"
                async with self.session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data:
                            name = entry['name_value'].lower()
                            if name.endswith(domain):
                                subdomains.add(name)
            except Exception as e:
                self.logger.error(f"Certificate search error: {str(e)}")

        # Run all enumeration methods concurrently
        await asyncio.gather(
            dns_brute_force(),
            certificate_search()
        )
        
        return {'subdomains': list(subdomains)}

    async def vulnerability_analysis(self, target: str, ports: List[Dict]) -> Dict:
        """Comprehensive vulnerability analysis"""
        vulnerabilities = []
        
        # Check each port for vulnerabilities
        for port in ports:
            service = port['service']
            version = port['version']
            
            # Check multiple vulnerability databases
            async def check_vuldb():
                # Implementation for vulnerability database check
                pass
                
            async def check_exploitdb():
                # Implementation for exploit-db check
                pass
                
            async def check_metasploit():
                # Implementation for Metasploit module check
                pass
                
            results = await asyncio.gather(
                check_vuldb(),
                check_exploitdb(),
                check_metasploit()
            )
            
            for result in results:
                if result:
                    vulnerabilities.extend(result)
                    
        return {'vulnerabilities': vulnerabilities}

    def process_geo_data(self, source: str, data: Dict) -> Dict:
        """Process and standardize geolocation data from different sources"""
        processed = {
            'country': None,
            'region': None,
            'city': None,
            'latitude': None,
            'longitude': None,
            'isp': None,
            'org': None
        }
        
        if source == 'ipapi':
            processed.update({
                'country': data.get('country_name'),
                'region': data.get('region'),
                'city': data.get('city'),
                'latitude': data.get('latitude'),
                'longitude': data.get('longitude'),
                'isp': data.get('org')
            })
        # Add processors for other sources
            
        return processed

    async def run_scan(self, target: str):
        """Main scanning function"""
        self.start_time = time.time()
        
        with Progress(
            SpinnerColumn(),
            *Progress.get_default_columns(),
            console=self.console
        ) as progress:
            # Setup progress bars
            port_task = progress.add_task("[cyan]Scanning ports...", total=None)
            geo_task = progress.add_task("[green]Gathering geolocation data...", total=None)
            sub_task = progress.add_task("[yellow]Enumerating subdomains...", total=None)
            vuln_task = progress.add_task("[red]Analyzing vulnerabilities...", total=None)
            
            # Run all scans concurrently
            results = await asyncio.gather(
                self.enhanced_port_scan(target),
                self.advanced_geo_ip(target),
                self.enhanced_subdomain_scan(target) if not target.replace('.', '').isdigit() else asyncio.sleep(0),
                return_exceptions=True
            )
            
            # Process results
            self.results = self.process_results(results)
            
            # Generate report
            self.generate_report(target)

    def process_results(self, results: List) -> Dict:
        """Process and combine all scan results"""
        processed = {}
        
        for result in results:
            if isinstance(result, Dict):
                processed.update(result)
            elif isinstance(result, Exception):
                self.logger.error(f"Scan error: {str(result)}")
                
        return processed

    def generate_report(self, target: str):
        """Generate comprehensive scan report"""
        duration = time.time() - self.start_time
        
        # Create main results table
        table = Table(title=f"Scan Results for {target}")
        table.add_column("Category", style="cyan")
        table.add_column("Findings", style="magenta")
        table.add_column("Risk Level", style="red")
        
        # Add rows based on results
        if 'ports' in self.results:
            table.add_row(
                "Open Ports",
                str(len(self.results['ports'])),
                self.calculate_risk_level(self.results['ports'])
            )
            
        if 'vulnerabilities' in self.results:
            table.add_row(
                "Vulnerabilities",
                str(len(self.results['vulnerabilities'])),
                self.calculate_risk_level(self.results['vulnerabilities'])
            )
            
        self.console.print(table)
        
        # Print detailed findings
        self.print_detailed_findings()
        
        # Save report to file
        self.save_report(target)

    def calculate_risk_level(self, findings: List) -> str:
        """Calculate risk level based on findings"""
        # Implementation for risk calculation
        return "HIGH"  # Placeholder

    def print_detailed_findings(self):
        """Print detailed scan findings"""
        self.console.print("\n[bold]Detailed Findings:[/bold]")
        
        # Print open ports
        if 'ports' in self.results:
            self.console.print("\n[cyan]Open Ports:[/cyan]")
            for port in self.results['ports']:
                self.console.print(
                    Panel(
                        f"Port: {port['port']}\n"
                        f"Service: {port['service']}\n"
                        f"Version: {port['version']}"
                    )
                )
                
        # Print vulnerabilities
        if 'vulnerabilities' in self.results:
            self.console.print("\n[red]Vulnerabilities:[/red]")
            for vuln in self.results['vulnerabilities']:
                self.console.print(Panel(str(vuln)))

    def save_report(self, target: str):
        """Save scan results to file"""
        filename = f"scan_report_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=4)
        self.console.print(f"\n[green]Report saved to {filename}[/green]")

    async def cleanup(self):
        """Cleanup resources"""
        await self.session.close()

async def main():
    scanner = NextGenScanner()
    console = Console()
    
    try:
        console.print("[bold cyan]NextGen Security Scanner[/bold cyan]")
        console.print("[bold cyan]========================[/bold cyan]\n")
        
        target = console.input("[yellow]Enter target to scan: [/yellow]")
        await scanner.run_scan(target)
        
    except KeyboardInterrupt:
        console.print("\n[red]Scan interrupted by user[/red]")
    except Exception as e:
        console.print(f"[red]Error during scan: {str(e)}[/red]")
    finally:
        await scanner.cleanup()

if __name__ == "__main__":
    asyncio.run(main())
