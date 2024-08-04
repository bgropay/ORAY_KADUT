from scapy.all import *
import os
import time

def change_channel(interface, channel):
    os.system(f"iwconfig {interface} channel {channel}")

def pkt_handler(pkt):
    if pkt.haslayer(Dot11Beacon):
        ssid = pkt[Dot11Elt].info.decode()
        bssid = pkt[Dot11].addr3
        channel = int(ord(pkt[Dot11Elt:3].info))
        if channel >= 1 and channel <= 13:  # Only consider 2.4 GHz channels
            print(f"SSID: {ssid}, BSSID: {bssid}, Channel: {channel}")

def main():
    interface = "wlan0mon"  # Change this to your wireless interface in monitor mode
    print("Scanning for 2.4 GHz Wi-Fi networks...")
    
    for channel in range(1, 14):  # Channels 1-13 for 2.4 GHz
        print(f"Switching to channel {channel}")
        change_channel(interface, channel)
        sniff(iface=interface, prn=pkt_handler, timeout=5)
        time.sleep(1)

if __name__ == "__main__":
    main()
  
