import phonenumbers
from phonenumbers import geocoder, carrier, timezone
import folium
import random

def show_logo():
    logo = """
    ███████╗██████╗ ██╗   ██╗███╗   ██╗ █████╗  ██████╗ 
    ██╔════╝██╔══██╗██║   ██║████╗  ██║██╔══██╗██╔════╝ 
    █████╗  ██████╔╝██║   ██║██╔██╗ ██║███████║██║  ███╗
    ██╔══╝  ██╔══██╗██║   ██║██║╚██╗██║██╔══██║██║   ██║
    ███████╗██║  ██║╚██████╔╝██║ ╚████║██║  ██║╚██████╔╝
    ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ 

           Mächtiges Ortungstool auf High-End-Niveau!
    """
    print(logo)

def locate_phone(phone_number):
    try:
        parsed_number = phonenumbers.parse(phone_number)

        # Validierung der Telefonnummer
        if not phonenumbers.is_valid_number(parsed_number):
            return {"Fehler": "Ungültige Telefonnummer"}

        # Standortinformationen
        country = geocoder.description_for_number(parsed_number, "en")
        timezones = timezone.time_zones_for_number(parsed_number)
        carrier_name = carrier.name_for_number(parsed_number, "en")

        # Simulierte Standortkoordinaten
        latitude = random.uniform(-90, 90)
        longitude = random.uniform(-180, 180)

        return {
            "Nummer": phone_number,
            "Land": country,
            "Zeitzone(n)": timezones,
            "Netzbetreiber": carrier_name,
            "Breitengrad": latitude,
            "Längengrad": longitude,
        }
    except Exception as e:
        return {"Fehler": str(e)}

def visualize_location(phone_info):
    try:
        if "Breitengrad" in phone_info and "Längengrad" in phone_info:
            lat = phone_info["Breitengrad"]
            lon = phone_info["Längengrad"]
            map_obj = folium.Map(location=[lat, lon], zoom_start=10)
            folium.Marker(
                location=[lat, lon],
                popup=(
                    f"Nummer: {phone_info['Nummer']}\n"
                    f"Land: {phone_info['Land']}\n"
                    f"Netzbetreiber: {phone_info['Netzbetreiber']}\n"
                    f"Zeitzone(n): {', '.join(phone_info['Zeitzone(n)'])}"
                ),
            ).add_to(map_obj)
            map_obj.save("phone_location_map.html")
            print("Karte wurde erfolgreich erstellt: phone_location_map.html")
        else:
            print("Unzureichende Standortdaten für die Visualisierung.")
    except Exception as e:
        print(f"Fehler bei der Kartenvisualisierung: {e}")

def main():
    show_logo()
    print("Telefonnummer-Ortungstool gestartet!")
    phone_number = input("Gib die Telefonnummer ein (mit Ländervorwahl, z. B. +49...): ")
    phone_info = locate_phone(phone_number)

    if "Fehler" in phone_info:
        print(f"Fehler: {phone_info['Fehler']}")
    else:
        for key, value in phone_info.items():
            print(f"{key}: {value}")
        visualize_location(phone_info)

if __name__ == "__main__":
    main()

