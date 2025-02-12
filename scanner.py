#!/usr/bin/env python3
"""
Modernes, erweitertes CLI-Tool: Schwachstellen-Scanner
--------------------------------------------------------
Dieses Tool führt einen parallelen Port-Scan (über einen ThreadPool),
asynchrone Web- und API-Scans (mittels aiohttp/asyncio) sowie einen Subdomain-Scan
durch. Die Ergebnisse werden anhand einer erweiterten Risikoabschätzung ausgewertet
und farblich formatiert in der Konsole ausgegeben. Optional kann ein PDF-Report erstellt werden.
Der interaktive Modus sorgt für eine benutzerfreundliche Eingabevalidierung.

Dieser Code enthält Verbesserungen in den Bereichen:
1. Fehler- und Ausnahmebehandlung
2. Eingabevalidierung und Parameterprüfung
4. Verbesserte Logging-Strategie
5. Optimierung der asynchronen Abläufe
"""

import argparse
import asyncio
import concurrent.futures
import logging
import re
import socket
from typing import Any, Dict, List, Tuple

import nmap
import requests
import aiohttp
from aiohttp import ClientTimeout, ClientSession
from bs4 import BeautifulSoup
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# Imports für verbesserte CLI-Ausgabe mit Rich
from rich.console import Console
from rich.table import Table

# Logging-Konfiguration
logging.basicConfig(
    level=logging.DEBUG,  # Setze auf DEBUG, um alle Meldungen zu erhalten
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)

# Rich-Konsole initialisieren
console = Console()

# Konfiguration: Definition kritischer und moderater Ports
CRITICAL_PORTS: Dict[int, Tuple[str, str]] = {
    23:    ("Telnet", "Kritisch"),
    3389:  ("RDP", "Kritisch"),
    1433:  ("MSSQL", "Kritisch"),
    5900:  ("VNC", "Kritisch"),
    3306:  ("MySQL", "Kritisch"),
    1521:  ("Oracle DB", "Kritisch"),
    27017: ("MongoDB", "Kritisch"),
    6379:  ("Redis", "Kritisch")
}

MODERATE_PORTS: Dict[int, Tuple[str, str]] = {
    21:   ("FTP", "Mittel"),
    22:   ("SSH", "Mittel"),
    25:   ("SMTP", "Mittel"),
    53:   ("DNS", "Mittel"),
    80:   ("HTTP", "Mittel"),
    443:  ("HTTPS", "Mittel"),
    389:  ("LDAP", "Mittel"),
    110:  ("POP3", "Mittel"),
    143:  ("IMAP", "Mittel"),
    993:  ("IMAP SSL", "Mittel")
}

# -------------------------------
# Modul: Port-Scan (parallel)
# -------------------------------
def port_scan(target: str, port_range: str) -> List[Dict[str, Any]]:
    """
    Führt einen Port-Scan mit nmap auf dem angegebenen Ziel im spezifizierten
    Portbereich durch und gibt eine Liste der gefundenen offenen Ports mit
    Dienst- und Risikoangaben zurück.
    """
    logging.info(f"[PORT-SCAN] Starte Scan für {target} im Bereich {port_range}")
    nm = nmap.PortScanner()
    try:
        nm.scan(target, arguments=f'-p {port_range} --open')
    except Exception as e:
        logging.error(f"[PORT-SCAN] Fehler beim Scan: {e}")
        console.print(f"[PORT-SCAN] Fehler beim Scan: {e}", style="bold red")
        return []
    results = []
    for host in nm.all_hosts():
        for port in nm[host]['tcp']:
            service = nm[host]['tcp'][port].get('name', 'unbekannt')
            state = nm[host]['tcp'][port].get('state', 'unbekannt')
            if port in CRITICAL_PORTS:
                risk = CRITICAL_PORTS[port][1]
            elif port in MODERATE_PORTS:
                risk = MODERATE_PORTS[port][1]
            else:
                risk = "Niedrig"
            results.append({"port": port, "service": service, "state": state, "risk": risk})
            style = "red" if risk == "Kritisch" else "yellow" if risk == "Mittel" else "green"
            console.print(f"[PORT-SCAN] Port {port}: {service} ({state}) - Risiko: {risk}", style=style)
    return results

# -------------------------------
# Modul: Asynchroner Web-Scan
# -------------------------------
async def web_scan_async(target: str, sema: asyncio.Semaphore) -> Dict[str, Tuple[str, str]]:
    """
    Führt einen asynchronen Web-Scan auf dem Ziel durch, prüft, ob HTTPS aktiv ist,
    kontrolliert wichtige HTTP-Sicherheitsheader und versucht, ein CMS anhand des Meta-Tags
    'generator' zu erkennen. Gibt ein Dictionary mit den Ergebnissen zurück.
    """
    logging.info(f"[WEB-SCAN] Asynchroner Scan für {target}")
    results: Dict[str, Tuple[str, str]] = {}
    url = target if target.startswith("http") else f"http://{target}"
    timeout = ClientTimeout(total=10)
    try:
        async with sema, ClientSession(timeout=timeout) as session:
            async with session.get(url) as response:
                final_url = str(response.url)
                text = await response.text()
                headers = response.headers
    except aiohttp.ClientError as e:
        logging.error(f"[WEB-SCAN] Netzwerkfehler: {e}")
        console.print(f"[WEB-SCAN] Netzwerkfehler: {e}", style="bold red")
        results["HTTPS"] = (f"Fehler: {e}", "Rot")
        return results
    except Exception as e:
        logging.error(f"[WEB-SCAN] Unerwarteter Fehler: {e}")
        console.print(f"[WEB-SCAN] Unerwarteter Fehler: {e}", style="bold red")
        results["HTTPS"] = (f"Fehler: {e}", "Rot")
        return results

    # HTTPS-Check
    if final_url.startswith("https"):
        results["HTTPS"] = ("Aktiv", "Grün")
        console.print("[WEB-SCAN] HTTPS: Aktiv", style="green")
    else:
        results["HTTPS"] = ("NICHT aktiv", "Rot")
        console.print("[WEB-SCAN] HTTPS: NICHT aktiv", style="red")

    # Erweiterte Header-Checks
    header_issues = []
    required_headers = {
        "Strict-Transport-Security": "HSTS",
        "X-Frame-Options": "Clickjacking-Schutz",
        "Content-Security-Policy": "CSP",
        "X-XSS-Protection": "XSS-Schutz",
        "X-Content-Type-Options": "MIME-Sniffing-Schutz",
        "Referrer-Policy": "Referrer Policy",
        "Permissions-Policy": "Feature Policy",
        "Expect-CT": "Certificate Transparency",
        "X-Permitted-Cross-Domain-Policies": "Cross-Domain Policy"
    }
    for header, desc in required_headers.items():
        if header not in headers:
            header_issues.append(f"Kein {header} ({desc})")
    if header_issues:
        results["Headers"] = (", ".join(header_issues), "Rot")
        console.print(f"[WEB-SCAN] Fehlende Header: {', '.join(header_issues)}", style="red")
    else:
        results["Headers"] = ("Alle sicherheitsrelevanten Header vorhanden", "Grün")
        console.print("[WEB-SCAN] Alle Sicherheitsheader vorhanden", style="green")

    # CMS-/Skript-Erkennung
    try:
        soup = BeautifulSoup(text, "html.parser")
        meta_generator = soup.find("meta", {"name": "generator"})
        if meta_generator and meta_generator.get("content"):
            cms = meta_generator["content"]
            results["CMS"] = (cms, "Gelb")
            console.print(f"[WEB-SCAN] CMS erkannt: {cms}", style="yellow")
        else:
            results["CMS"] = ("Nicht erkannt", "Grün")
            console.print("[WEB-SCAN] CMS: Nicht erkannt", style="green")
    except Exception as e:
        logging.error(f"[WEB-SCAN] CMS-Erkennung Fehler: {e}")
        console.print(f"[WEB-SCAN] CMS-Erkennung Fehler: {e}", style="bold red")
        results["CMS"] = (f"Fehler: {e}", "Rot")
    return results

# -------------------------------
# Modul: Asynchroner API-Scan
# -------------------------------
async def api_scan_async(target: str, sema: asyncio.Semaphore) -> List[Dict[str, Any]]:
    """
    Führt einen asynchronen Scan gängiger API-Endpunkte auf dem Ziel durch.
    Für jeden Endpunkt wird geprüft, ob er erreichbar ist (Statuscode 200) und
    entsprechend als kritisch oder niedrig eingestuft. Gibt eine Liste der Ergebnisse zurück.
    """
    logging.info(f"[API-SCAN] Asynchroner API-Scan für {target}")
    endpoints = [
        "/api/", "/api/v1/", "/api/v2/", "/api/v3/", "/api/v4/",
        "/rest/", "/graphql", "/wp-json/", "/odata/"
    ]
    results: List[Dict[str, Any]] = []
    base_url = target if target.startswith("http") else f"http://{target}"
    timeout = ClientTimeout(total=5)
    async with sema, ClientSession(timeout=timeout) as session:
        for endpoint in endpoints:
            full_url = base_url.rstrip("/") + endpoint
            try:
                async with session.get(full_url) as response:
                    if response.status == 200:
                        results.append({"endpoint": full_url, "status": response.status, "risk": "Kritisch"})
                        console.print(f"[API-SCAN] Offener API-Endpunkt: {full_url} (Status: {response.status}) - Risiko: Kritisch", style="red")
                    else:
                        results.append({"endpoint": full_url, "status": response.status, "risk": "Niedrig"})
                        console.print(f"[API-SCAN] Endpunkt {full_url} antwortet mit Status {response.status}", style="green")
            except aiohttp.ClientError as e:
                logging.warning(f"[API-SCAN] {full_url} nicht erreichbar: {e}")
                console.print(f"[API-SCAN] Endpunkt {full_url} nicht erreichbar ({e})", style="yellow")
            except Exception as e:
                logging.warning(f"[API-SCAN] Unerwarteter Fehler bei {full_url}: {e}")
                console.print(f"[API-SCAN] Unerwarteter Fehler bei {full_url}: {e}", style="yellow")
    if not results:
        console.print("[API-SCAN] Keine offenen API-Endpunkte gefunden.", style="green")
    return results

# -------------------------------
# Modul: Subdomain-Scan
# -------------------------------
def subdomain_scan(target: str) -> List[Dict[str, str]]:
    """
    Führt einen Subdomain-Scan auf dem Ziel durch, indem eine Liste gängiger Subdomains
    abgefragt wird. Für jeden Kandidaten wird versucht, den DNS-Namen aufzulösen.
    Gibt eine Liste gefundener Subdomains mit der zugehörigen IP-Adresse zurück.
    """
    logging.info(f"[SUBDOMAIN] Starte Subdomain-Scan für {target}")
    common_subdomains = [
        "www", "mail", "ftp", "dev", "test", "api", "blog", "m", "admin", 
        "secure", "vpn", "webmail", "shop", "beta", "portal", "support", "forum", "demo"
    ]
    found: List[Dict[str, str]] = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_sub = {executor.submit(socket.gethostbyname, f"{sub}.{target}"): sub for sub in common_subdomains}
        for future in concurrent.futures.as_completed(future_to_sub):
            sub = future_to_sub[future]
            try:
                ip = future.result()
                found.append({"subdomain": f"{sub}.{target}", "ip": ip})
                console.print(f"[SUBDOMAIN] {sub}.{target} resolved to {ip}", style="green")
            except Exception:
                console.print(f"[SUBDOMAIN] {sub}.{target} nicht gefunden", style="yellow")
    return found

# -------------------------------
# Modul: Erweiterte Risikoabschätzung
# -------------------------------
def assess_risk(port_results: List[Dict[str, Any]], web_results: Dict[str, Tuple[str, str]],
                api_results: List[Dict[str, Any]]) -> str:
    """
    Berechnet einen Risiko-Score basierend auf den Ergebnissen des Port-, Web- und API-Scans.
    Je höher der Score, desto kritischer wird das Ziel eingestuft.
    """
    score = 0
    for entry in port_results:
        if entry["risk"] == "Kritisch":
            score += 3
        elif entry["risk"] == "Mittel":
            score += 2
        else:
            score += 1
    if web_results.get("HTTPS", ("",))[0] != "Aktiv":
        score += 3
    if "Kein" in web_results.get("Headers", ("",))[0]:
        score += 2
    for entry in api_results:
        if entry["risk"] == "Kritisch":
            score += 3
    if score >= 12:
        risk_level = "Kritisch"
    elif score >= 8:
        risk_level = "Hoch"
    elif score >= 4:
        risk_level = "Mittel"
    else:
        risk_level = "Niedrig"
    console.print(f"\n[RISIKO] Gesamtrisikobewertung: {risk_level} (Score: {score})", style="magenta")
    return risk_level

# -------------------------------
# Modul: PDF-Report-Erstellung
# -------------------------------
def generate_pdf_report(target: str, port_results: List[Dict[str, Any]], web_results: Dict[str, Tuple[str, str]],
                        api_results: List[Dict[str, Any]], subdomain_results: List[Dict[str, str]], risk_level: str,
                        filename: str = "scan_report.pdf") -> None:
    """
    Erzeugt einen PDF-Report, der alle Scan-Ergebnisse (Port-, Web-, API- und Subdomain-Scan)
    sowie die Gesamtbewertung übersichtlich darstellt.
    """
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter
    y = height - 50
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "Security Scan Report")
    c.setFont("Helvetica", 12)
    y -= 30
    c.drawString(50, y, f"Ziel: {target}")
    y -= 20
    c.drawString(50, y, f"Gesamtrisikobewertung: {risk_level}")
    y -= 30

    # Port-Scan-Ergebnisse
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Port-Scan Ergebnisse:")
    y -= 20
    c.setFont("Helvetica", 10)
    for entry in port_results:
        c.drawString(60, y, f"Port {entry['port']}: {entry['service']} ({entry['state']}) - Risiko: {entry['risk']}")
        y -= 15
        if y < 50:
            c.showPage()
            y = height - 50
    y -= 10

    # Web-Scan-Ergebnisse
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Web-Scan Ergebnisse:")
    y -= 20
    c.setFont("Helvetica", 10)
    for key, (value, _) in web_results.items():
        c.drawString(60, y, f"{key}: {value}")
        y -= 15
        if y < 50:
            c.showPage()
            y = height - 50
    y -= 10

    # API-Scan-Ergebnisse
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "API-Scan Ergebnisse:")
    y -= 20
    c.setFont("Helvetica", 10)
    for entry in api_results:
        c.drawString(60, y, f"Endpoint: {entry['endpoint']} - Status: {entry['status']} - Risiko: {entry['risk']}")
        y -= 15
        if y < 50:
            c.showPage()
            y = height - 50
    y -= 10

    # Subdomain-Scan-Ergebnisse
    if subdomain_results:
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, "Subdomain-Scan Ergebnisse:")
        y -= 20
        c.setFont("Helvetica", 10)
        for sub in subdomain_results:
            c.drawString(60, y, f"{sub['subdomain']} - IP: {sub['ip']}")
            y -= 15
            if y < 50:
                c.showPage()
                y = height - 50

    c.save()
    console.print(f"\n[REPORT] PDF-Report erstellt: {filename}", style="cyan")

# -------------------------------
# Verbesserter Interaktiver Modus (mit Validierung)
# -------------------------------
def interactive_mode() -> Tuple[str, bool, bool, bool, bool, str, bool]:
    """
    Startet den interaktiven Modus und fragt den Benutzer schrittweise nach den
    benötigten Parametern. Es erfolgt eine Eingabevalidierung.
    """
    console.print("\n[INTERAKTIV] Starte interaktiven Modus...", style="cyan")
    # Ziel eingeben und validieren (prüfen, ob DNS-Auflösung möglich ist)
    while True:
        target = input("Gib die Ziel-IP oder Domain ein: ").strip()
        if target:
            try:
                socket.gethostbyname(target)
                break
            except socket.gaierror:
                console.print("Fehler: Domain kann nicht aufgelöst werden. Bitte versuche es erneut.", style="bold red")
        else:
            console.print("Fehler: Ziel darf nicht leer sein.", style="bold red")
    port_choice = input("Port-Scan durchführen? (y/n): ").strip().lower() == "y"
    web_choice  = input("Web-Scan durchführen? (y/n): ").strip().lower() == "y"
    api_choice  = input("API-Scan durchführen? (y/n): ").strip().lower() == "y"
    subdomain_choice = input("Subdomain-Scan durchführen? (y/n): ").strip().lower() == "y"
    ports = input("Gib den Portbereich ein (Standard 1-1024): ").strip() or "1-1024"
    # Validierung: Portbereich muss dem Muster "min-max" entsprechen
    if not re.fullmatch(r"\d+-\d+", ports):
        console.print("Ungültiges Format für Portbereich. Standard 1-1024 wird verwendet.", style="red")
        ports = "1-1024"
    pdf_choice = input("PDF-Report erstellen? (y/n): ").strip().lower() == "y"
    return target, port_choice, web_choice, api_choice, subdomain_choice, ports, pdf_choice

# -------------------------------
# Hauptfunktion: CLI-Interface und Scan-Steuerung
# -------------------------------
def main() -> None:
    """
    Parst die CLI-Argumente oder startet den interaktiven Modus, führt die
    ausgewählten Scans (Port, Web, API, Subdomain) parallel bzw. asynchron aus und
    erstellt abschließend eine Risikoabschätzung sowie optional einen PDF-Report.
    """
    parser = argparse.ArgumentParser(description="Modernes, erweitertes CLI-basiertes Schwachstellen-Scanner-Tool")
    parser.add_argument("--target", help="Ziel-IP oder Domain (z.B. example.com oder 192.168.1.1)")
    parser.add_argument("--port-scan", action="store_true", help="Führe Port-Scan durch")
    parser.add_argument("--web-scan", action="store_true", help="Führe Web-Scan durch")
    parser.add_argument("--api-scan", action="store_true", help="Führe API-Scan durch")
    parser.add_argument("--subdomain-scan", action="store_true", help="Führe Subdomain-Scan durch")
    parser.add_argument("--ports", default="1-1024", help="Portbereich (z.B. 1-1024)")
    parser.add_argument("--pdf", action="store_true", help="Erstelle PDF-Report")
    parser.add_argument("--interactive", action="store_true", help="Starte interaktiven Modus")
    
    args = parser.parse_args()
    
    if args.interactive or not args.target:
        target, port_choice, web_choice, api_choice, subdomain_choice, ports, pdf_choice = interactive_mode()
    else:
        target = args.target
        port_choice = args.port_scan
        web_choice = args.web_scan
        api_choice = args.api_scan
        subdomain_choice = args.subdomain_scan
        ports = args.ports
        pdf_choice = args.pdf

    port_results: List[Dict[str, Any]] = []
    web_results: Dict[str, Tuple[str, str]] = {}
    api_results: List[Dict[str, Any]] = []
    subdomain_results: List[Dict[str, str]] = []
    
    # Port-Scan via ThreadPool (parallel)
    if port_choice:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_port = executor.submit(port_scan, target, ports)
            port_results = future_port.result()
    
    # Asynchrone Web- und API-Scans mit Concurrency-Begrenzung
    semaphore = asyncio.Semaphore(5)
    async def run_async_scans() -> None:
        nonlocal web_results, api_results
        tasks = []
        if web_choice:
            tasks.append(web_scan_async(target, semaphore))
        if api_choice:
            tasks.append(api_scan_async(target, semaphore))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        if web_choice and results:
            web_results = results[0]
            if api_choice and len(results) > 1:
                api_results = results[1]
        elif api_choice:
            api_results = results[0]
    asyncio.run(run_async_scans())
    
    # Subdomain-Scan (parallel)
    if subdomain_choice:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_sub = executor.submit(subdomain_scan, target)
            subdomain_results = future_sub.result()
    
    risk_level = assess_risk(port_results, web_results, api_results)
    if pdf_choice:
        generate_pdf_report(target, port_results, web_results, api_results, subdomain_results, risk_level)
    
    logging.info(f"Scan abgeschlossen für Ziel: {target} | Port-Scan: {port_choice} | Web-Scan: {web_choice} | "
                 f"API-Scan: {api_choice} | Subdomain-Scan: {subdomain_choice} | Risikobewertung: {risk_level}")

if __name__ == "__main__":
    main()
