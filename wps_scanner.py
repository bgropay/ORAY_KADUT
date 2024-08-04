from scapy.all import *

def pkt_handler(pkt):
    if pkt.haslayer(Dot11Beacon):
        if pkt.haslayer(Dot11Elt):
            ssid = pkt[Dot11Elt].info.decode()
            bssid = pkt[Dot11].addr3
            for elt in pkt[Dot11Elt]:
                if elt.ID == 221 and elt.info.startswith(b'\x00\x50\xf2\x04'):
                    print(f"SSID: {ssid}, BSSID: {bssid}, WPS Detected")

def main():
    iface = "wlan0"  # Change this to your wireless interface in monitor mode
    print("Scanning for WPS enabled networks...")
    sniff(iface=iface, prn=pkt_handler, timeout=30)

if __name__ == "__main__":
    main()
