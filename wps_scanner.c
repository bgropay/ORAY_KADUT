#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

// Define the WPS OUI
const uint8_t WPS_OUI[] = { 0x00, 0x50, 0xf2, 0x04 };

// Function to handle captured packets
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;

    // Check if the packet is a 802.11 management frame
    if (ntohs(eth_header->ether_type) == 0x88c7) {
        // Skip RadioTap header
        const u_char *dot11_frame = packet + 18;

        // Check if it's a Beacon frame
        if ((dot11_frame[0] & 0x0c) == 0x08) {
            const u_char *ssid = dot11_frame + 36;
            const u_char *bssid = dot11_frame + 16;

            // Look for Vendor Specific Information Element
            const u_char *tag = dot11_frame + 36 + ssid[1] + 2;
            int tag_length = header->caplen - (tag - packet);

            while (tag_length > 2) {
                if (tag[0] == 221 && tag[1] >= 4 && memcmp(tag + 2, WPS_OUI, 4) == 0) {
                    printf("SSID: ");
                    fwrite(ssid + 2, 1, ssid[1], stdout);
                    printf(", BSSID: %02x:%02x:%02x:%02x:%02x:%02x, WPS Detected\n",
                           bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
                    break;
                }
                tag_length -= tag[1] + 2;
                tag += tag[1] + 2;
            }
        }
    }
}

int main() {
    char *dev = "wlan0";  // Change to your wireless interface
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Open the session in promiscuous mode
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    // Start packet processing loop
    pcap_loop(handle, 0, packet_handler, NULL);

    // Close the session
    pcap_close(handle);
    return 0;
}
