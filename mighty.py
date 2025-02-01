#!/usr/bin/env python3
"""
MightyScanner CLI – Ultimate Edition 2.0 (Interactive Wizard, Bilingual)
---------------------------------------------------------------------------
Das ultimative, terminalbasierte Netzwerkscanner-Tool.
Beim Start erscheint ein animiertes Banner. Anschließend wählt der Nutzer
seine Sprache (Englisch oder Deutsch) und wird dann durch einen interaktiven Wizard
geführt, der in nummerierten Menüs den Scan-Typ, das Ziel, den Portbereich und weitere Optionen abfragt.
Die Ergebnisse werden kompakt zusammengefasst ausgegeben.
 
ACHTUNG: Dieses Tool darf ausschließlich in autorisierten Netzwerken verwendet werden!
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
# Sprachwahl und Übersetzungen
##########################################
def select_language() -> str:
    lang_choice = Prompt.ask("[bold]Select language / Sprache auswählen[/bold] (1: English, 2: Deutsch)", choices=["1", "2"], default="1")
    return "en" if lang_choice == "1" else "de"

LANG = select_language()

# Übersetzungs-Dictionary: Alle Texte, die im interaktiven Wizard und anderen Prompts verwendet werden.
TEXT = {
    "en": {
        "welcome": "Welcome to the interactive MightyScanner Wizard!",
        "instruction": "Please follow the instructions. You can always accept the default values.",
        "enter_target": "1. Enter target(s) (e.g. 192.168.1.1, example.com, 192.168.1.0/24 or filename)",
        "enter_ports": "2. Enter port range (e.g. 22,80,8000-8100)",
        "choose_scan": "3. Choose the scan type:",
        "scan_options": {
            "1": ("TCP Connect", "Establishes a full TCP connection. Results: Port status, banner (optional)."),
            "2": ("SYN", "Sends a SYN packet without completing the connection. Results: Port status, OS fingerprint, banner (optional)."),
            "3": ("UDP", "Sends a UDP packet. Results: No response may indicate open or filtered."),
            "4": ("Null", "Sends a packet with no TCP flags. Stealth mode."),
            "5": ("FIN", "Sends a FIN packet. Open ports typically do not respond."),
            "6": ("XMAS", "Sends a packet with FIN, PSH, and URG flags. Stealth mode for detecting open ports."),
            "7": ("ACK", "Sends an ACK packet. Detects filtering."),
            "8": ("Fragment", "Sends fragmented packets to bypass firewalls."),
            "9": ("Aggressive", "Combines TCP Connect and SYN scans. Results: Comprehensive info including OS fingerprint and vulnerability hints.")
        },
        "your_choice": "Your choice (1-9)",
        "host_discovery": "4. Perform host discovery (Ping)? (y/n)",
        "banner_grabbing": "5. Enable banner grabbing? (y/n)",
        "timeout": "6. Enter timeout in seconds",
        "concurrency": "7. Maximum concurrent tasks",
        "output_format": "8. Choose output format (json, csv, xml, html)",
        "output_file": "9. Enter filename for saving results (leave empty if not desired)",
        "verbose": "10. Enable verbose mode? (y/n)",
        "scan_loading": "Loading",
        "scan_complete": "Scan complete!",
        "summary_title": "Summary",
        "save_results": "Save results to a file? (y/n)",
        "enter_filename": "Enter filename (e.g. results.json)",
        "thank_you": "Thank you for using MightyScanner CLI – Ultimate Edition 2.0!"
    },
    "de": {
        "welcome": "Willkommen beim interaktiven MightyScanner Wizard!",
        "instruction": "Bitte folge den Anweisungen. Du kannst jederzeit die vorgeschlagenen Standardwerte übernehmen.",
        "enter_target": "1. Gib die Ziel(e) ein (z. B. 192.168.1.1, example.com, 192.168.1.0/24 oder Dateiname)",
        "enter_ports": "2. Gib den Portbereich ein (z. B. 22,80,8000-8100)",
        "choose_scan": "3. Wähle den Scan-Typ aus:",
        "scan_options": {
            "1": ("TCP Connect", "Stellt eine vollständige TCP-Verbindung her. Ergebnis: Portstatus, Banner (optional)."),
            "2": ("SYN", "Sendet ein SYN-Paket ohne vollständige Verbindung. Ergebnis: Portstatus, OS-Fingerprint, Banner (optional)."),
            "3": ("UDP", "Sendet ein UDP-Paket. Ergebnis: Keine Antwort kann offen oder gefiltert bedeuten."),
            "4": ("Null", "Sendet ein Paket ohne gesetzte TCP-Flags. Stealth-Modus."),
            "5": ("FIN", "Sendet ein FIN-Paket. Offene Ports antworten meist nicht."),
            "6": ("XMAS", "Sendet ein Paket mit FIN, PSH und URG. Stealth-Modus zur Erkennung offener Ports."),
            "7": ("ACK", "Sendet ein ACK-Paket. Erkennt Filterung."),
            "8": ("Fragment", "Sendet fragmentierte Pakete zur Umgehung von Firewalls."),
            "9": ("Aggressive", "Kombiniert TCP Connect und SYN-Scan. Ergebnis: Umfassende Informationen inkl. OS-Fingerprint und Vulnerability-Hinweisen.")
        },
        "your_choice": "Deine Wahl (1-9)",
        "host_discovery": "4. Soll eine Host Discovery (Ping) durchgeführt werden? (y/n)",
        "banner_grabbing": "5. Soll Banner Grabbing aktiviert werden? (y/n)",
        "timeout": "6. Timeout in Sekunden",
        "concurrency": "7. Max. gleichzeitige Tasks",
        "output_format": "8. Ausgabeformat (json, csv, xml, html)",
        "output_file": "9. Dateiname zur Speicherung (leer lassen, falls nicht gewünscht)",
        "verbose": "10. Verbose Mode aktivieren? (y/n)",
        "scan_loading": "Lade",
        "scan_complete": "Scan abgeschlossen!",
        "summary_title": "Zusammenfassung",
        "save_results": "Ergebnisse in eine Datei speichern? (y/n)",
        "enter_filename": "Dateiname (z. B. results.json)",
        "thank_you": "Vielen Dank, dass Sie MightyScanner CLI – Ultimate Edition 2.0 verwenden!"
    }
}

def t(key: str) -> str:
    """Hilfsfunktion für Übersetzungen."""
    return TEXT[LANG].get(key, key)

##########################################
# Banner-Animation beim Start
##########################################
def display_banner():
    banner_art = r"""
  __  __ _       _   _       ____                                  
 |  \/  (_)_ __ | |_(_) ___ / ___|  ___ __ _ _ __  _ __   ___ _ __  
 | |\/| | | '_ \| __| |/ __| \___ \ / __/ _` | '_ \| '_ \ / _ \ '__| 
 | |  | | | | | | |_| | (__   ___) | (_| (_| | | | | | | |  __/ |    
 |_|  |_|_|_| |_|\__|_|\___| |____/ \___\__,_|_| |_|_| |_|\___|_|    
"""
    banner_title = "Mintic Scanner"
    panel = Panel(banner_art + "\n" + f"[bold white]{banner_title}[/bold white]", title="", subtitle=t("scan_loading") + " 0%", style="bold white")
    with Live(panel, refresh_per_second=10, screen=True) as live:
        for i in range(0, 101, 10):
            color = ["red", "orange1", "yellow", "green", "blue", "magenta"][i % 6]
            panel.title = f"[bold {color}]{banner_title}[/bold {color}]"
            panel.subtitle = f"[green]{t('scan_loading')} {i}%[/green]"
            live.update(panel)
            time.sleep(0.1)
    console.print(Align.center(panel))
    time.sleep(1)

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
    task_id = progress.add_task(f"Scanning {target}", total=len(tasks))
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
    os_info = unique_os.pop() if len(unique_os) == 1 else ("Mixed" if len(unique_os) > 1 else "N/A")
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
        table = Table(title=f"Results for {target}", show_lines=True)
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
        console.print(f"[green]Results saved to '{output_file}'.[/green]")
    except Exception as e:
        console.print(f"[red]Error writing to '{output_file}': {e}[/red]")

##########################################
# Interaktiver Wizard – Nummeriertes Menü mit Methodenerklärungen
##########################################
def interactive_wizard() -> argparse.Namespace:
    console.print(f"[bold blue]{TEXT[LANG]['welcome']}[/bold blue]")
    console.print(f"[italic]{TEXT[LANG]['instruction']}[/italic]\n")
    
    target = Prompt.ask(f"[bold]{TEXT[LANG]['enter_target']}[/bold]", default="127.0.0.1")
    if os.path.isfile(target):
        try:
            with open(target, "r") as f:
                targets_raw = f.read().strip()
            target = targets_raw.replace("\n", ",")
            console.print("[green]Targets successfully read from file.[/green]" if LANG=="en" else "[green]Ziele aus Datei erfolgreich gelesen.[/green]")
        except Exception as e:
            console.log(f"[red]Error reading file: {e}[/red]" if LANG=="en" else f"[red]Fehler beim Lesen der Datei: {e}[/red]")
    
    ports = Prompt.ask(f"[bold]{TEXT[LANG]['enter_ports']}[/bold]", default="1-1024")
    
    console.print(f"\n[bold]{TEXT[LANG]['choose_scan']}[/bold]")
    menu_options = {
        "1": ("TCP Connect", "Establishes a full TCP connection. Results: Port status, banner (optional)." if LANG=="en" else "Stellt eine vollständige TCP-Verbindung her. Ergebnis: Portstatus, Banner (optional)."),
        "2": ("SYN", "Sends a SYN packet without completing the connection. Results: Port status, OS fingerprint, banner (optional)." if LANG=="en" else "Sendet ein SYN-Paket ohne vollständige Verbindung. Ergebnis: Portstatus, OS-Fingerprint, Banner (optional)."),
        "3": ("UDP", "Sends a UDP packet. Results: No response may indicate open or filtered." if LANG=="en" else "Sendet ein UDP-Paket. Ergebnis: Keine Antwort kann offen oder gefiltert bedeuten."),
        "4": ("Null", "Sends a packet with no TCP flags. Stealth mode." if LANG=="en" else "Sendet ein Paket ohne gesetzte TCP-Flags. Stealth-Modus."),
        "5": ("FIN", "Sends a FIN packet. Open ports typically do not respond." if LANG=="en" else "Sendet ein FIN-Paket. Offene Ports antworten meist nicht."),
        "6": ("XMAS", "Sends a packet with FIN, PSH and URG flags. Stealth mode for detecting open ports." if LANG=="en" else "Sendet ein Paket mit FIN, PSH und URG. Stealth-Modus zur Erkennung offener Ports."),
        "7": ("ACK", "Sends an ACK packet to detect filtering." if LANG=="en" else "Sendet ein ACK-Paket. Erkennt Filterung."),
        "8": ("Fragment", "Sends fragmented packets to bypass firewalls." if LANG=="en" else "Sendet fragmentierte Pakete zur Umgehung von Firewalls."),
        "9": ("Aggressive", "Combines TCP Connect and SYN scans. Results: Comprehensive info including OS fingerprint and vulnerability hints." if LANG=="en" else "Kombiniert TCP Connect und SYN-Scan. Ergebnis: Umfassende Informationen inkl. OS-Fingerprint und Vulnerability-Hinweisen.")
    }
    for key, (name, desc) in menu_options.items():
        console.print(f"[yellow]   {key}.[/yellow] {name} - {desc}")
    choice = Prompt.ask(f"[bold]{TEXT[LANG]['your_choice']}[/bold]", choices=[str(i) for i in range(1, 10)], default="1")
    scan_type = menu_options[choice][0].lower()
    console.print(f"[italic green]You selected '{menu_options[choice][0]}': {menu_options[choice][1]}[/italic green]" if LANG=="en" else f"[italic green]Du hast '{menu_options[choice][0]}' gewählt: {menu_options[choice][1]}[/italic green]\n")
    
    host_disc_input = Prompt.ask(f"[bold]{TEXT[LANG]['host_discovery']}[/bold]", choices=["y", "n"], default="n")
    host_discovery_flag = True if host_disc_input.lower() == "y" else False
    
    grab_banner_input = Prompt.ask(f"[bold]{TEXT[LANG]['banner_grabbing']}[/bold]", choices=["y", "n"], default="n")
    grab_banner = True if grab_banner_input.lower() == "y" else False
    
    timeout = float(Prompt.ask(f"[bold]{TEXT[LANG]['timeout']}[/bold]", default="1.0"))
    concurrency = int(Prompt.ask(f"[bold]{TEXT[LANG]['concurrency']}[/bold]", default="500"))
    output_format = Prompt.ask(f"[bold]{TEXT[LANG]['output_format']}[/bold]", choices=["json", "csv", "xml", "html"], default="json")
    output_file = Prompt.ask(f"[bold]{TEXT[LANG]['output_file']}[/bold]", default="")
    verbose_input = Prompt.ask(f"[bold]{TEXT[LANG]['verbose']}[/bold]", choices=["y", "n"], default="n")
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
    panel = Panel(splash_art, title="[bold magenta]Mintic Scanner CLI – Ultimate Edition 2.0[/bold magenta]",
                  subtitle=f"[green]{TEXT[LANG]['scan_loading']} 0%[/green]", style="bold blue")
    with Live(panel, refresh_per_second=10, screen=True) as live:
        for i in range(0, 101, 10):
            panel.title = f"[bold magenta]Mintic Scanner CLI – Ultimate Edition 2.0[/bold magenta]"
            panel.subtitle = f"[green]{TEXT[LANG]['scan_loading']} {i}%[/green]"
            live.update(panel)
            time.sleep(0.1)
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
            description="Mintic Scanner CLI – Ultimate Edition 2.0: A high-end network scanner for the terminal",
            epilog="Use only in authorized networks!"
        )
        parser.add_argument("target", help="Target(s): Single host, comma-separated list, CIDR or filename")
        parser.add_argument("-p", "--ports", default="1-1024", help="Ports to scan (e.g. '22,80,8000-8100'). Default: 1-1024")
        parser.add_argument("-s", "--scan-type", choices=["connect", "syn", "udp", "null", "fin", "xmas", "ack", "fragment", "aggressive"], default="connect",
                            help="Scan type: connect, syn, udp, null, fin, xmas, ack, fragment or aggressive")
        parser.add_argument("--banner", action="store_true", help="Enable banner grabbing")
        parser.add_argument("--timeout", type=float, default=1.0, help="Timeout in seconds (default: 1.0)")
        parser.add_argument("--concurrency", type=int, default=500, help="Maximum concurrent tasks (default: 500)")
        parser.add_argument("--host-discovery", action="store_true", help="Perform host discovery (Ping) before scanning")
        parser.add_argument("-f", "--format", choices=["json", "csv", "xml", "html"], default="json",
                            help="Output format (default: json)")
        parser.add_argument("-o", "--output", help="Filename to save results")
        parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
        parser.add_argument("--interactive", action="store_true", help="Interactive mode (Wizard)")
        args = parser.parse_args()

    display_splash()

    if args.verbose:
        console.print("[bold blue]Verbose Mode activated.[/bold blue]")

    targets_raw = parse_targets(args.target)
    if getattr(args, "host_discovery", False):
        console.print("[bold yellow]Performing host discovery...[/bold yellow]" if LANG=="en" else "[bold yellow]Führe Host Discovery durch...[/bold yellow]")
        targets_up = [t for t in targets_raw if host_is_up(t)]
        console.print(f"[green]Reachable targets: {targets_up}[/green]" if LANG=="en" else f"[green]Erreichbare Ziele: {targets_up}[/green]")
        targets = targets_up
    else:
        targets = targets_raw

    ports = parse_ports(args.ports)
    console.print(f"[bold green]Targets:[/bold green] {targets}")
    console.print(f"[bold green]Ports:[/bold green] {ports[0]} to {ports[-1]} (total {len(ports)})" if LANG=="en" else f"[bold green]Ports:[/bold green] {ports[0]} bis {ports[-1]} (insgesamt {len(ports)})")
    console.print(f"[bold green]Scan type:[/bold green] {args.scan_type}" if LANG=="en" else f"[bold green]Scan-Typ:[/bold green] {args.scan_type}")
    console.print("\n")

    if args.scan_type in ["syn", "udp", "null", "fin", "xmas", "ack", "fragment", "aggressive"] and os.geteuid() != 0:
        console.print("[yellow]Warning: Root privileges are usually required for the selected scan type![/yellow]" if LANG=="en" else "[yellow]Achtung: Für den gewählten Scan-Typ sind in der Regel Root-Rechte erforderlich![/yellow]")

    overall_results = await scan_all_targets(targets, ports, args.scan_type, args.timeout, args.banner, args.concurrency)
    console.print(f"\n[bold green]{TEXT[LANG]['scan_complete']}[/bold green]\n")
    print_results(overall_results)

    summary_table = Table(title=TEXT[LANG]["summary_title"], show_lines=True)
    summary_table.add_column("Target", style="cyan")
    summary_table.add_column("Hostname", style="magenta")
    summary_table.add_column("Scanned Ports", justify="right", style="yellow")
    summary_table.add_column("Open Ports (#)", justify="right", style="green")
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
        save_choice = Prompt.ask(TEXT[LANG]["save_results"], choices=["y", "n"], default="n")
        if save_choice.lower() == "y":
            file_name = Prompt.ask(TEXT[LANG]["enter_filename"])
            output_results(overall_results, args.format, file_name)

    console.print(f"[bold magenta]{TEXT[LANG]['thank_you']}[/bold magenta]")

def aggregate_target_info(target: str, results: list) -> dict:
    total_scanned = len(results)
    open_ports = [str(r["port"]) for r in results if r["status"] == "open"]
    os_list = [r["os"] for r in results if r["status"] == "open" and r["os"]]
    unique_os = set(os_list)
    os_info = unique_os.pop() if len(unique_os) == 1 else ("Mixed" if len(unique_os) > 1 else "N/A")
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
        console.print("[red]Scan interrupted by user.[/red]" if LANG=="en" else "[red]Scan durch Benutzer unterbrochen.[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
