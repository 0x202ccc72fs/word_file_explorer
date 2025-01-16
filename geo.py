import socket
import requests
import json
import folium
import platform
import os
from subprocess import check_output
from time import sleep

# Funktion: Großes Spynac-Logo anzeigen
def show_logo():
    logo = """
    ███████╗██████╗ ██╗   ██╗███╗   ██╗ █████╗  ██████╗ 
    ██╔════╝██╔══██╗██║   ██║████╗  ██║██╔══██╗██╔════╝ 
    █████╗  ██████╔╝██║   ██║██╔██╗ ██║███████║██║  ███╗
    ██╔══╝  ██╔══██╗██║   ██║██║╚██╗██║██╔══██║██║   ██║
    ███████╗██║  ██║╚██████╔╝██║ ╚████║██║  ██║╚██████╔╝
    ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ 

                  Mächtiges Ortungstool
    """
    print(logo)
    sleep(2)

# Funktion: Erweiterte IP-Ortung
def locate_ip(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        additional_response = requests.get(f"http://ip-api.com/json/{ip}")
        if response.status_code == 200 and additional_response.status_code == 200:
            data = response.json()
            additional_data = additional_response.json()
            return {
                "IP": ip,
                "Stadt": data.get("city", "Unbekannt"),
                "Region": data.get("region", "Unbekannt"),
                "Land": data.get("country", "Unbekannt"),
                "Postleitzahl": data.get("postal", "Unbekannt"),
                "Latitude, Longitude": data.get("loc", "Unbekannt"),
                "Organisation": data.get("org", "Unbekannt"),
                "ISP": additional_data.get("isp", "Unbekannt"),
                "Zeitzone": additional_data.get("timezone", "Unbekannt"),
                "AS": additional_data.get("as", "Unbekannt")
            }
        else:
            return {"Fehler": "IP-Informationen konnten nicht abgerufen werden."}
    except Exception as e:
        return {"Fehler": str(e)}

# Funktion: Telefonnummer orten mit umfassender Analyse
def locate_phone(phone):
    try:
        response = requests.get(f"https://api.telnyx.com/v2/number_lookup/{phone}")
        if response.status_code == 200:
            data = response.json()
            return {
                "Telefonnummer": phone,
                "Land": data.get("country_code", "Unbekannt"),
                "Region": data.get("national_format", "Unbekannt"),
                "Carrier": data.get("carrier", {}).get("name", "Unbekannt"),
                "Linetyp": data.get("carrier", {}).get("type", "Unbekannt"),
                "Gültig": data.get("valid", "Unbekannt")
            }
        else:
            return {"Fehler": "Telefoninformationen konnten nicht abgerufen werden."}
    except Exception as e:
        return {"Fehler": str(e)}

# Funktion: DNS-Informationen abrufen
def dns_info(domain):
    try:
        ip = socket.gethostbyname(domain)
        return {
            "Domain": domain,
            "IP": ip,
            "Reverse-DNS": reverse_dns(ip)
        }
    except Exception as e:
        return {"Fehler": f"DNS-Auflösung fehlgeschlagen: {str(e)}"}

# Funktion: Reverse DNS Lookup
def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Kein Reverse-DNS verfügbar"

# Funktion: MAC-Adresse und lokales Netzwerk scannen
def get_mac_and_network():
    try:
        if platform.system() == "Windows":
            arp_output = check_output("arp -a", shell=True).decode()
            return {"Netzwerk-Scan": arp_output}
        elif platform.system() in ["Linux", "Darwin"]:
            arp_output = check_output(["arp", "-n"]).decode()
            return {"Netzwerk-Scan": arp_output}
        else:
            return {"Fehler": "Plattform nicht unterstützt"}
    except Exception as e:
        return {"Fehler": str(e)}

# Funktion: Karte visualisieren
def visualize_location(ip_info):
    try:
        loc = ip_info.get("Latitude, Longitude")
        if loc != "Unbekannt":
            lat, lon = map(float, loc.split(","))
            map_obj = folium.Map(location=[lat, lon], zoom_start=10)
            folium.Marker(
                location=[lat, lon],
                popup=(
                    f"IP: {ip_info['IP']}\n"
                    f"Stadt: {ip_info['Stadt']}\n"
                    f"Region: {ip_info['Region']}\n"
                    f"Land: {ip_info['Land']}\n"
                    f"Postleitzahl: {ip_info['Postleitzahl']}\n"
                    f"Organisation: {ip_info['Organisation']}\n"
                    f"ISP: {ip_info['ISP']}\n"
                    f"Zeitzone: {ip_info['Zeitzone']}\n"
                    f"AS: {ip_info['AS']}"
                ),
            ).add_to(map_obj)
            map_obj.save("location_map.html")
            print("Karte wurde erfolgreich erstellt: location_map.html")
        else:
            print("Standortdaten unvollständig, Karte nicht erstellt.")
    except Exception as e:
        print(f"Fehler bei der Kartenvisualisierung: {e}")

# Hauptprogramm
def main():
    show_logo()
    print("Optionen: 1) IP orten, 2) Domain analysieren, 3) Lokales Netzwerk scannen, 4) Telefonnummer orten")
    choice = input("Wähle eine Option: ")

    if choice == "1":
        ip = input("Gib eine IP-Adresse ein: ")
        ip_info = locate_ip(ip)
        print(json.dumps(ip_info, indent=4, ensure_ascii=False))
        if "Fehler" not in ip_info:
            visualize_location(ip_info)

    elif choice == "2":
        domain = input("Gib eine Domain ein: ")
        domain_info = dns_info(domain)
        print(json.dumps(domain_info, indent=4, ensure_ascii=False))

    elif choice == "3":
        network_info = get_mac_and_network()
        print(json.dumps(network_info, indent=4, ensure_ascii=False))

    elif choice == "4":
        phone = input("Gib eine Telefonnummer ein: ")
        phone_info = locate_phone(phone)
        print(json.dumps(phone_info, indent=4, ensure_ascii=False))

    else:
        print("Ungültige Auswahl.")

if __name__ == "__main__":
    main()
