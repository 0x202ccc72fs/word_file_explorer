#!/usr/bin/env python3
"""
MightyScanner CLI – Ultimate Edition 2.0 (Userfriendly & Kompakt)
------------------------------------------------------------------
Das ultimative, terminalbasierte Netzwerkscanner-Tool – jetzt mit noch mehr Informationen
zum Ziel in einer kompakten Zusammenfassung.

Funktionen:
  • Multi‑Target‑Scanning (Einzelhost, kommagetrennte Liste, CIDR oder aus Datei)
  • Vorab-Host‑Discovery (Ping) und Reverse DNS Lookup
  • Scan‑Modi:
         - connect: Asynchroner TCP‑Connect‑Scan (optional mit Banner Grabbing)
         - syn: SYN‑Scan via Scapy (mit heuristischem OS‑Fingerprinting)
         - udp: UDP‑Scan via Scapy
         - null: Null Scan (keine Flags – stealthy)
         - fin: FIN Scan (stealth)
         - xmas: XMAS Scan (FIN, PSH, URG gesetzt)
         - ack: ACK Scan (zur Filtererkennung)
         - fragment: Fragmentierter Scan (um Firewalls zu umgehen)
         - aggressive: Kombiniert TCP‑Connect und SYN‑Scan
  • Interaktiver Wizard‑Modus mit ausführlichen, farbigen Anweisungen
  • Ergebnisse werden kompakt zusammengefasst:
         - Anzahl gescannter Ports, offene Ports, OS-Fingerprint und Vulnerability-Hinweise
  • Flexible Ausgabeformate (JSON, CSV, XML, HTML)
 
ACHTUNG: Nur in autorisierten Netzwerken verwenden!
"""

import argparse
import asyncio
import socket
import ipaddress
import time
import sys
import os
import json
import csv
import subprocess
from html import escape

from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.live import Live
from rich.prompt import Prompt

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

try:
    from scapy.all import IP, TCP, UDP, ICMP, sr1, send, traceroute as scapy_traceroute
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

console = Console()

##########################################
# Zusatzfunktionen: Host Discovery & Reverse DNS
##########################################

def host_is_up(target: str) -> bool:
    """Führt einen Ping-Test durch, um zu prüfen, ob ein Host erreichbar ist."""
    try:
        result = subprocess.run(["ping", "-c", "1", "-W", "1", target],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode == 0
    except Exception:
        return False

def reverse_dns(target: str) -> str:
    """Ermittelt den FQDN (Hostname) des Ziels."""
    try:
        hostname, _, _ = socket.gethostbyaddr(target)
        return hostname
    except Exception:
        return ""

##########################################
# Zusatzfunktionen: Advanced OS Fingerprint & Vulnerability Scan
##########################################

def advanced_os_fingerprint(ttl, window) -> str:
    """
    Heuristisches OS‑Fingerprinting basierend auf TTL und TCP‑Fenstergröße.
    (Diese Werte sind grobe Indikatoren.)
    """
    if ttl is None or window is None:
        return "Unknown"
    if ttl <= 64:
        if window in [5840, 14600]:
            return "Linux (wahrscheinlich)"
        return "Linux/Unix"
    elif ttl <= 128:
        if window in [8192]:
            return "Windows (wahrscheinlich)"
        return "Windows"
    elif ttl <= 255:
        return "Netzwerkgerät/Firewall"
    return "Unknown"

def vulnerability_scan(target, port) -> str:
    """Platzhalterhafte Vulnerability Detection für bekannte Ports."""
    vuln_ports = {
        21: "FTP: Default Credentials möglich",
        23: "Telnet: Unsicher",
        25: "SMTP: Mögliche Spoofing-Risiken",
        80: "HTTP: Potenzielle Schwachstellen",
        443: "HTTPS: SSL/TLS-Konfiguration prüfen"
    }
    return vuln_ports.get(port, "")

##########################################
# Parsing-Funktionen für Targets & Ports
##########################################

def parse_targets(target_str: str) -> list:
    """
    Parst Zieldefinitionen (Einzelhost, kommagetrennte Liste, CIDR).
    Liefert eine sortierte Liste eindeutiger Ziele.
    """
    targets = set()
    for part in target_str.split(','):
        part = part.strip()
        if "/" in part:
            try:
                net = ipaddress.ip_network(part, strict=False)
                for ip in net.hosts():
                    targets.add(str(ip))
            except Exception as e:
                console.log(f"[red]Fehler beim Parsen des Netzes '{part}': {e}[/red]")
        else:
            targets.add(part)
    return sorted(targets)

def parse_ports(port_str: str) -> list:
    """
    Parst eine Portangabe (z. B. "22,80,8000-8100") in eine sortierte Liste von Portnummern.
    """
    ports = set()
    for part in port_str.split(','):
        part = part.strip()
        if '-' in part:
            try:
                start, end = part.split('-')
                ports.update(range(int(start), int(end) + 1))
            except Exception as e:
                console.log(f"[red]Fehler beim Parsen des Portbereichs '{part}': {e}[/red]")
        else:
            try:
                ports.add(int(part))
            except Exception as e:
                console.log(f"[red]Fehler beim Parsen des Ports '{part}': {e}[/red]")
    return sorted(ports)

##########################################
# Scan-Funktionen – Verschiedene Methoden
##########################################

async def tcp_connect_scan_async(target: str, port: int, timeout: float, grab_banner: bool) -> dict:
    result = {"port": port, "status": "closed", "banner": ""}
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(target, port), timeout=timeout)
        result["status"] = "open"
        if grab_banner:
            try:
                banner = await asyncio.wait_for(reader.read(1024), timeout=timeout)
                result["banner"] = banner.decode(errors="ignore").strip()
            except Exception:
                result["banner"] = ""
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass
    return result

def tcp_syn_scan_sync(target: str, port: int, timeout: float, grab_banner: bool) -> dict:
    result = {"port": port, "status": "closed", "banner": "", "ttl": None, "window": None}
    if not SCAPY_AVAILABLE:
        return result
    pkt = IP(dst=target) / TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=timeout, verbose=0)
    if resp and resp.haslayer(TCP):
        tcp_layer = resp.getlayer(TCP)
        if tcp_layer.flags == 0x12:
            rst_pkt = IP(dst=target) / TCP(dport=port, flags="R")
            send(rst_pkt, verbose=0)
            result["status"] = "open"
            result["ttl"] = resp.getlayer(IP).ttl
            result["window"] = tcp_layer.window
            if grab_banner:
                result["banner"] = grab_banner_sync(target, port, timeout)
    return result

def udp_scan_sync(target: str, port: int, timeout: float) -> dict:
    result = {"port": port, "status": "closed", "banner": ""}
    if not SCAPY_AVAILABLE:
        return result
    pkt = IP(dst=target) / UDP(dport=port)
    resp = sr1(pkt, timeout=timeout, verbose=0)
    if resp is None:
        result["status"] = "open"
    elif resp.haslayer(ICMP):
        icmp_layer = resp.getlayer(ICMP)
        if int(icmp_layer.type) == 3 and int(icmp_layer.code) in [1,2,3,9,10,13]:
            result["status"] = "closed"
    return result

def tcp_null_scan_sync(target: str, port: int, timeout: float, grab_banner: bool) -> dict:
    result = {"port": port, "status": "closed", "banner": ""}
    if not SCAPY_AVAILABLE:
        return result
    pkt = IP(dst=target) / TCP(dport=port, flags="")
    resp = sr1(pkt, timeout=timeout, verbose=0)
    if resp is None:
        result["status"] = "open"
    elif resp.haslayer(TCP):
        result["status"] = "closed"
    return result

def tcp_fin_scan_sync(target: str, port: int, timeout: float, grab_banner: bool) -> dict:
    result = {"port": port, "status": "closed", "banner": ""}
    if not SCAPY_AVAILABLE:
        return result
    pkt = IP(dst=target) / TCP(dport=port, flags="F")
    resp = sr1(pkt, timeout=timeout, verbose=0)
    if resp is None:
        result["status"] = "open"
    elif resp.haslayer(TCP):
        result["status"] = "closed"
    return result

def tcp_xmas_scan_sync(target: str, port: int, timeout: float, grab_banner: bool) -> dict:
    result = {"port": port, "status": "closed", "banner": ""}
    if not SCAPY_AVAILABLE:
        return result
    pkt = IP(dst=target) / TCP(dport=port, flags="FPU")
    resp = sr1(pkt, timeout=timeout, verbose=0)
    if resp is None:
        result["status"] = "open"
    elif resp.haslayer(TCP):
        result["status"] = "closed"
    return result

def tcp_ack_scan_sync(target: str, port: int, timeout: float, grab_banner: bool) -> dict:
    result = {"port": port, "status": "filtered", "banner": ""}
    if not SCAPY_AVAILABLE:
        return result
    pkt = IP(dst=target) / TCP(dport=port, flags="A")
    resp = sr1(pkt, timeout=timeout, verbose=0)
    if resp is None:
        result["status"] = "filtered"
    elif resp.haslayer(TCP):
        if resp.getlayer(TCP).flags & 0x04:
            result["status"] = "unfiltered"
        else:
            result["status"] = "filtered"
    return result

def tcp_fragment_scan_sync(target: str, port: int, timeout: float, grab_banner: bool) -> dict:
    result = {"port": port, "status": "closed", "banner": ""}
    if not SCAPY_AVAILABLE:
        return result
    pkt = IP(dst=target) / TCP(dport=port, flags="S")
    frags = pkt.fragment()
    for frag in frags:
        send(frag, verbose=0)
    resp = sr1(pkt, timeout=timeout, verbose=0)
    if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
        rst_pkt = IP(dst=target) / TCP(dport=port, flags="R")
        send(rst_pkt, verbose=0)
        result["status"] = "open"
        if grab_banner:
            result["banner"] = grab_banner_sync(target, port, timeout)
    return result

async def aggressive_scan_port_async(target: str, port: int, timeout: float, grab_banner: bool) -> dict:
    task_connect = asyncio.create_task(tcp_connect_scan_async(target, port, timeout, grab_banner))
    task_syn = asyncio.create_task(asyncio.to_thread(tcp_syn_scan_sync, target, port, timeout, grab_banner))
    results = await asyncio.gather(task_connect, task_syn)
    status = "open" if any(r.get("status") == "open" for r in results) else "closed"
    banner = results[1].get("banner") if results[1].get("banner") else results[0].get("banner")
    os_fp = advanced_os_fingerprint(results[1].get("ttl"), results[1].get("window")) if results[1].get("status") == "open" else ""
    vuln = vulnerability_scan(target, port) if status == "open" else ""
    return {"port": port, "status": status, "banner": banner, "os": os_fp, "vuln": vuln}

async def scan_port_async(target: str, port: int, scan_type: str, timeout: float, grab_banner: bool) -> dict:
    if scan_type == "connect":
        return await tcp_connect_scan_async(target, port, timeout, grab_banner)
    elif scan_type == "syn":
        return await asyncio.to_thread(tcp_syn_scan_sync, target, port, timeout, grab_banner)
    elif scan_type == "udp":
        return await asyncio.to_thread(udp_scan_sync, target, port, timeout)
    elif scan_type == "null":
        return await asyncio.to_thread(tcp_null_scan_sync, target, port, timeout, grab_banner)
    elif scan_type == "fin":
        return await asyncio.to_thread(tcp_fin_scan_sync, target, port, timeout, grab_banner)
    elif scan_type == "xmas":
        return await asyncio.to_thread(tcp_xmas_scan_sync, target, port, timeout, grab_banner)
    elif scan_type == "ack":
        return await asyncio.to_thread(tcp_ack_scan_sync, target, port, timeout, grab_banner)
    elif scan_type == "fragment":
        return await asyncio.to_thread(tcp_fragment_scan_sync, target, port, timeout, grab_banner)
    elif scan_type == "aggressive":
        return await aggressive_scan_port_async(target, port, timeout, grab_banner)
    else:
        return {"port": port, "status": "unknown", "banner": ""}

async def scan_target(target: str, ports: list, scan_type: str, timeout: float, grab_banner: bool, concurrency: int) -> list:
    results = []
    sem = asyncio.Semaphore(concurrency)
    async def sem_scan(port: int) -> dict:
        async with sem:
            res = await scan_port_async(target, port, scan_type, timeout, grab_banner)
            if scan_type in ["syn", "aggressive"] and res.get("status") == "open":
                res["os"] = advanced_os_fingerprint(res.get("ttl"), res.get("window"))
            else:
                res["os"] = ""
            res["vuln"] = vulnerability_scan(target, port) if res.get("status") == "open" else ""
            return res
    tasks = [asyncio.create_task(sem_scan(port)) for port in ports]
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn()
    )
    task_id = progress.add_task(f"Scanne {target}", total=len(tasks))
    with progress:
        for coro in asyncio.as_completed(tasks):
            res = await coro
            results.append(res)
            progress.advance(task_id)
    return sorted(results, key=lambda x: x["port"])

async def scan_all_targets(targets: list, ports: list, scan_type: str, timeout: float, grab_banner: bool, concurrency: int) -> dict:
    overall = {}
    for target in targets:
        overall[target] = await scan_target(target, ports, scan_type, timeout, grab_banner, concurrency)
    return overall

##########################################
# Aggregation der Zielinformationen (Kompakte Zusammenfassung)
##########################################

def aggregate_target_info(target: str, results: list) -> dict:
    total_scanned = len(results)
    open_ports = [str(r["port"]) for r in results if r["status"] == "open"]
    os_list = [r["os"] for r in results if r["status"] == "open" and r["os"]]
    unique_os = set(os_list)
    if len(unique_os) == 1:
         os_info = unique_os.pop()
    elif len(unique_os) > 1:
         os_info = "Mixed"
    else:
         os_info = "N/A"
    vuln_list = [r["vuln"] for r in results if r["status"] == "open" and r["vuln"]]
    unique_vuln = ", ".join(sorted(set(vuln_list))) if vuln_list else "None"
    return {
         "scanned": total_scanned,
         "open_ports": ", ".join(open_ports) if open_ports else "None",
         "open_count": len(open_ports),
         "os": os_info,
         "vuln": unique_vuln
    }

##########################################
# Ausgabe der Ergebnisse & Zusammenfassung
##########################################

def print_results(overall_results: dict):
    for target, results in overall_results.items():
        table = Table(title=f"Ergebnisse für {target}", show_lines=True)
        table.add_column("Port", justify="right", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Banner", style="yellow")
        table.add_column("OS", style="blue")
        table.add_column("Vuln", style="red")
        for res in results:
            table.add_row(
                str(res.get("port")),
                res.get("status"),
                res.get("banner"),
                res.get("os"),
                res.get("vuln")
            )
        console.print(table)

def output_results(data: dict, output_format: str, output_file: str):
    if output_format == "json":
        out_str = json.dumps(data, indent=4)
    elif output_format == "csv":
        lines = ["target,port,status,banner,os,vuln"]
        for tgt, results in data.items():
            for res in results:
                line = f'{tgt},{res.get("port")},{res.get("status")},"{res.get("banner", "").replace(chr(10), " ")}",{res.get("os")},{res.get("vuln")}'
                lines.append(line)
        out_str = "\n".join(lines)
    elif output_format == "xml":
        lines = ["<scan>"]
        for tgt, results in data.items():
            lines.append(f'  <target name="{escape(tgt)}">')
            for res in results:
                lines.append(f'    <port number="{res.get("port")}" status="{res.get("status")}">')
                lines.append(f'      <banner>{escape(res.get("banner", ""))}</banner>')
                lines.append(f'      <os>{escape(res.get("os", ""))}</os>')
                lines.append(f'      <vuln>{escape(res.get("vuln", ""))}</vuln>')
                lines.append("    </port>")
            lines.append("  </target>")
        lines.append("</scan>")
        out_str = "\n".join(lines)
    elif output_format == "html":
        lines = ['<html><head><meta charset="UTF-8"><title>Scan Results</title></head><body>']
        for tgt, results in data.items():
            lines.append(f"<h2>Target: {tgt} ({reverse_dns(tgt)})</h2>")
            lines.append("<table border='1'><tr><th>Port</th><th>Status</th><th>Banner</th><th>OS</th><th>Vuln</th></tr>")
            for res in results:
                lines.append("<tr>")
                lines.append(f"<td>{res.get('port')}</td>")
                lines.append(f"<td>{res.get('status')}</td>")
                lines.append(f"<td>{res.get('banner')}</td>")
                lines.append(f"<td>{res.get('os')}</td>")
                lines.append(f"<td>{res.get('vuln')}</td>")
                lines.append("</tr>")
            lines.append("</table>")
        lines.append("</body></html>")
        out_str = "\n".join(lines)
    else:
        out_str = json.dumps(data, indent=4)
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(out_str)
        console.print(f"[green]Ergebnisse in '{output_file}' gespeichert.[/green]")
    except Exception as e:
        console.print(f"[red]Fehler beim Schreiben in '{output_file}': {e}[/red]")

##########################################
# Interaktiver Wizard (Benutzerfreundliche Eingabe)
##########################################

def interactive_wizard() -> argparse.Namespace:
    console.print("[bold blue]Willkommen beim interaktiven MightyScanner Wizard![/bold blue]")
    console.print("Bitte folge den Anweisungen. Du kannst jederzeit die vorgeschlagenen Standardwerte übernehmen.")
    target = Prompt.ask("[bold]Ziel(e) eingeben[/bold] (z. B. 192.168.1.1, example.com, 192.168.1.0/24 oder Dateiname)", default="127.0.0.1")
    if os.path.isfile(target):
        try:
            with open(target, "r") as f:
                targets_raw = f.read().strip()
            target = targets_raw.replace("\n", ",")
            console.print("[green]Ziele aus Datei erfolgreich gelesen.[/green]")
        except Exception as e:
            console.log(f"[red]Fehler beim Lesen der Datei: {e}[/red]")
    ports = Prompt.ask("[bold]Portbereich eingeben[/bold] (z. B. 22,80,8000-8100)", default="1-1024")
    scan_type = Prompt.ask("[bold]Scan-Typ wählen[/bold]", choices=["connect", "syn", "udp", "null", "fin", "xmas", "ack", "fragment", "aggressive"], default="connect")
    host_disc_input = Prompt.ask("[bold]Host Discovery durchführen?[/bold] (Ping) (y/n)", choices=["y", "n"], default="n")
    host_discovery_flag = True if host_disc_input.lower() == "y" else False
    grab_banner_input = Prompt.ask("[bold]Banner Grabbing aktivieren?[/bold] (y/n)", choices=["y", "n"], default="n")
    grab_banner = True if grab_banner_input.lower() == "y" else False
    timeout = float(Prompt.ask("[bold]Timeout[/bold] in Sekunden", default="1.0"))
    concurrency = int(Prompt.ask("[bold]Max. gleichzeitige Tasks[/bold]", default="500"))
    output_format = Prompt.ask("[bold]Ausgabeformat[/bold]", choices=["json", "csv", "xml", "html"], default="json")
    output_file = Prompt.ask("[bold]Dateiname zur Speicherung[/bold] (leer lassen, falls nicht gewünscht)", default="")
    verbose_input = Prompt.ask("[bold]Verbose Mode aktivieren?[/bold] (y/n)", choices=["y", "n"], default="n")
    verbose = True if verbose_input.lower() == "y" else False

    args = argparse.Namespace(
        target=target,
        ports=ports,
        scan_type=scan_type,
        banner=grab_banner,
        timeout=timeout,
        concurrency=concurrency,
        format=output_format,
        output=output_file if output_file.strip() != "" else None,
        verbose=verbose,
        host_discovery=host_discovery_flag,
        interactive=True
    )
    return args

##########################################
# Splashscreen (Banner) und Animation
##########################################

def display_splash():
    splash_art = r"""
  __  __ _       _   _       ____                                  
 |  \/  (_)_ __ | |_(_) ___ / ___|  ___ __ _ _ __  _ __   ___ _ __  
 | |\/| | | '_ \| __| |/ __| \___ \ / __/ _` | '_ \| '_ \ / _ \ '__| 
 | |  | | | | | | |_| | (__   ___) | (_| (_| | | | | | | |  __/ |    
 |_|  |_|_|_| |_|\__|_|\___| |____/ \___\__,_|_| |_|_| |_|\___|_|    
"""
    panel = Panel(splash_art, title="[bold magenta]MightyScanner CLI – Ultimate Edition 2.0[/bold magenta]",
                  subtitle="[green]Das mächtigste Netzwerkscanner-Tool der Welt[/green]",
                  style="bold blue")
    # Animation: Ladeeffekt simulieren
    with Live(panel, refresh_per_second=4, screen=True) as live:
        for i in range(0, 101, 10):
            panel.title = f"[bold magenta]MightyScanner CLI – Ultimate Edition 2.0[/bold magenta] [yellow]Lade {i}%[/yellow]"
            live.update(panel)
            time.sleep(0.3)
    console.print(Align.center(panel))
    time.sleep(1)

##########################################
# Hauptprogramm
##########################################

async def main_async():
    if len(sys.argv) == 1 or "--interactive" in sys.argv:
        args = interactive_wizard()
    else:
        parser = argparse.ArgumentParser(
            description="MightyScanner CLI – Ultimate Edition 2.0: Ein High-End Netzwerkscanner für das Terminal",
            epilog="Nur in autorisierten Netzwerken verwenden!"
        )
        parser.add_argument("target", help="Target(s): Einzelhost, kommagetrennte Liste, CIDR oder Dateiname mit Zielen")
        parser.add_argument("-p", "--ports", default="1-1024", help="Ports zum Scannen (z. B. '22,80,8000-8100'). Standard: 1-1024")
        parser.add_argument("-s", "--scan-type", choices=["connect", "syn", "udp", "null", "fin", "xmas", "ack", "fragment", "aggressive"], default="connect",
                            help="Scan-Typ: connect, syn, udp, null, fin, xmas, ack, fragment oder aggressive")
        parser.add_argument("--banner", action="store_true", help="Aktiviere Banner Grabbing")
        parser.add_argument("--timeout", type=float, default=1.0, help="Timeout in Sekunden (Standard: 1.0)")
        parser.add_argument("--concurrency", type=int, default=500, help="Max. gleichzeitige Tasks (Standard: 500)")
        parser.add_argument("--host-discovery", action="store_true", help="Host Discovery (Ping) vor dem Scan durchführen")
        parser.add_argument("-f", "--format", choices=["json", "csv", "xml", "html"], default="json",
                            help="Ausgabeformat (Standard: json)")
        parser.add_argument("-o", "--output", help="Datei, in die die Ergebnisse geschrieben werden sollen")
        parser.add_argument("-v", "--verbose", action="store_true", help="Ausführliche Log-Ausgaben")
        parser.add_argument("--interactive", action="store_true", help="Interaktiver Eingabemodus (Wizard)")
        args = parser.parse_args()

    display_splash()

    if args.verbose:
        console.print("[bold blue]Verbose Mode aktiviert.[/bold blue]")

    targets_raw = parse_targets(args.target)
    if getattr(args, "host_discovery", False):
        console.print("[bold yellow]Führe Host Discovery durch...[/bold yellow]")
        targets_up = [t for t in targets_raw if host_is_up(t)]
        console.print(f"[green]Erreichbare Ziele: {targets_up}[/green]")
        targets = targets_up
    else:
        targets = targets_raw

    ports = parse_ports(args.ports)
    console.print(f"[bold green]Targets:[/bold green] {targets}")
    console.print(f"[bold green]Ports:[/bold green] {ports[0]} bis {ports[-1]} (insgesamt {len(ports)})")
    console.print(f"[bold green]Scan-Typ:[/bold green] {args.scan_type}\n")

    if args.scan_type in ["syn", "udp", "null", "fin", "xmas", "ack", "fragment", "aggressive"] and os.geteuid() != 0:
        console.print("[yellow]Achtung: Für den gewählten Scan-Typ sind in der Regel Root-Rechte erforderlich![/yellow]")

    overall_results = await scan_all_targets(targets, ports, args.scan_type, args.timeout, args.banner, args.concurrency)
    console.print("[bold green]Scan abgeschlossen![/bold green]\n")
    print_results(overall_results)

    # Erstelle eine kompakte Zusammenfassung pro Ziel
    summary_table = Table(title="Zusammenfassung der Zielinformationen", show_lines=True)
    summary_table.add_column("Target", style="cyan")
    summary_table.add_column("Hostname", style="magenta")
    summary_table.add_column("Gescannte Ports", justify="right", style="yellow")
    summary_table.add_column("Offene Ports (#)", justify="right", style="green")
    summary_table.add_column("OS", style="blue")
    summary_table.add_column("Vulnerabilities", style="red")
    for tgt, results in overall_results.items():
        agg = aggregate_target_info(tgt, results)
        summary_table.add_row(
            tgt,
            reverse_dns(tgt) or "N/A",
            str(agg["scanned"]),
            f'{agg["open_count"]} ({agg["open_ports"]})',
            agg["os"],
            agg["vuln"]
        )
    console.print(summary_table)

    if args.output:
        output_results(overall_results, args.format, args.output)
    else:
        save_choice = Prompt.ask("Ergebnisse in eine Datei speichern? (y/n)", choices=["y", "n"], default="n")
        if save_choice.lower() == "y":
            file_name = Prompt.ask("Dateiname (z. B. results.json)")
            output_results(overall_results, args.format, file_name)

    console.print("[bold magenta]Vielen Dank, dass Sie MightyScanner CLI – Ultimate Edition 2.0 verwenden![/bold magenta]")

def aggregate_target_info(target: str, results: list) -> dict:
    total_scanned = len(results)
    open_ports = [str(r["port"]) for r in results if r["status"] == "open"]
    os_list = [r["os"] for r in results if r["status"] == "open" and r["os"]]
    unique_os = set(os_list)
    if len(unique_os) == 1:
         os_info = unique_os.pop()
    elif len(unique_os) > 1:
         os_info = "Mixed"
    else:
         os_info = "N/A"
    vuln_list = [r["vuln"] for r in results if r["status"] == "open" and r["vuln"]]
    unique_vuln = ", ".join(sorted(set(vuln_list))) if vuln_list else "None"
    return {
         "scanned": total_scanned,
         "open_ports": ", ".join(open_ports) if open_ports else "None",
         "open_count": len(open_ports),
         "os": os_info,
         "vuln": unique_vuln
    }

def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        console.print("[red]Scan durch Benutzer unterbrochen.[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
