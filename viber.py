import pyshark
from colorama import init, Fore, Style
import socket

# Inicializálja a colorama-t (szükséges Windows alatt)
init()

# Az interfész kiválasztása (pl. "Wi-Fi")
interface = "Wi-Fi"  # Helyettesítsd a megfelelő interfész nevével

# Élő forgalom figyelése STUN csomagokra
capture = pyshark.LiveCapture(interface=interface, display_filter="stun")

print("STUN csomagok figyelése...\n")
for packet in capture.sniff_continuously():
    try:
        if "STUN" in packet:
            # STUN réteg elérése
            stun_layer = packet["STUN"]

            # Forrás és cél IP-címek elérése
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst

            # IP címek visszafejtése a hostnevekké
            try:
                src_host = socket.gethostbyaddr(src_ip)[0]  # Forrás IP reverse lookup
            except socket.herror:
                src_host = "Nincs információ"

            try:
                dst_host = socket.gethostbyaddr(dst_ip)[0]  # Cél IP reverse lookup
            except socket.herror:
                dst_host = "Nincs információ"

            # Ellenőrizzük, hogy a type mező értéke 0x0101
            if hasattr(stun_layer, 'type'):
                type_value = stun_layer.type
                if type_value == "0x0101":
                    # Zöld színnel kiemelve a forrás IP-cím
                    print(f"Új STUN csomag:")
                    print(f"{Fore.GREEN}  Target IP: {src_ip} ({src_host}){Style.RESET_ALL}")
                else:
                    # Normál színnel írjuk ki a forrás IP-t
                    print(f"Új STUN csomag:")
                    print(f"  Forrás IP: {src_ip} ({src_host})")

                # A cél IP-cím mindig normál színű
                print(f"  Cél IP: {dst_ip} ({dst_host})")

                # STUN attribútumok kiíratása
                for field in stun_layer.field_names:
                    value = stun_layer.get_field_value(field)
                    print(f"  {field}: {value}")

                # Két sortörés minden csomag után
                print("\n\n")
            else:
                print("A csomag nem tartalmaz 'type' mezőt.\n\n")
    except AttributeError:
        # Előfordulhat, hogy egy csomagban nincs IP-réteg
        print("IP réteg nem található a csomagban.\n\n")
    except Exception as e:
        print(f"Hiba történt: {e}\n\n")
