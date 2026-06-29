#!/usr/bin/env python3
"""
wifi_recon.py - Passive Wi-Fi recon for authorized security testing.

Listens for 802.11 beacon/probe-response frames on a monitor-mode interface
and reports nearby access points: SSID, BSSID, channel, signal strength, and
encryption type (Open / WEP / WPA / WPA2 / WPA3). Purely passive: it never
transmits a packet.

Requirements:
  - Linux with a wireless adapter that supports monitor mode.
  - The interface must already be in monitor mode, e.g.:
      sudo airmon-ng start wlan0
  - scapy:  pip install scapy
  - Run as root (raw 802.11 capture requires elevated privileges).

Usage:
  sudo python3 wifi_recon.py -i wlan0mon
  sudo python3 wifi_recon.py -i wlan0mon --duration 30 --csv scan_results.csv

Only use this against networks you own or are explicitly authorized to test.
"""
import argparse
import csv
import sys
import time

try:
    from scapy.all import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, RadioTap, sniff
except ImportError:
    sys.exit("scapy is required: pip install scapy")


def get_channel(packet):
    elt = packet.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 3 and len(elt.info) == 1:  # DS Parameter Set
            return elt.info[0]
        elt = elt.payload.getlayer(Dot11Elt)
    return None


def get_encryption(packet):
    cap = packet[Dot11Beacon].cap if packet.haslayer(Dot11Beacon) else packet[Dot11ProbeResp].cap
    privacy = "privacy" in cap

    has_rsn = False
    has_wpa = False
    elt = packet.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 48:  # RSN -> WPA2/WPA3
            has_rsn = True
        if elt.ID == 221 and elt.info.startswith(b"\x00\x50\xf2\x01"):  # vendor WPA
            has_wpa = True
        elt = elt.payload.getlayer(Dot11Elt)

    if has_rsn:
        return "WPA2/WPA3"
    if has_wpa:
        return "WPA"
    if privacy:
        return "WEP"
    return "Open"


def get_signal(packet):
    try:
        return packet[RadioTap].dBm_AntSignal
    except (IndexError, AttributeError):
        return None


def main():
    parser = argparse.ArgumentParser(description="Passive Wi-Fi AP recon (authorized testing only)")
    parser.add_argument("-i", "--interface", required=True, help="Monitor-mode interface, e.g. wlan0mon")
    parser.add_argument("--duration", type=int, default=20, help="Seconds to scan (default: 20)")
    parser.add_argument("--csv", help="Optional path to write results as CSV")
    args = parser.parse_args()

    networks = {}

    def handle_packet(packet):
        if not (packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp)):
            return
        bssid = packet[Dot11].addr2
        if bssid in networks:
            return

        try:
            ssid = packet[Dot11Elt].info.decode(errors="replace") or "<hidden>"
        except Exception:
            ssid = "<hidden>"

        networks[bssid] = {
            "ssid": ssid,
            "bssid": bssid,
            "channel": get_channel(packet),
            "encryption": get_encryption(packet),
            "signal_dbm": get_signal(packet),
        }
        row = networks[bssid]
        print(f"[+] {row['bssid']}  ch={row['channel']!s:<3} "
              f"{row['encryption']:<10} {row['signal_dbm']!s:>5} dBm  {row['ssid']}")

    print(f"Scanning on {args.interface} for {args.duration}s (passive, authorized testing only)...\n")
    sniff(iface=args.interface, prn=handle_packet, timeout=args.duration, store=False)

    print(f"\nFound {len(networks)} network(s).")

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["ssid", "bssid", "channel", "encryption", "signal_dbm"])
            writer.writeheader()
            writer.writerows(networks.values())
        print(f"Results written to {args.csv}")


if __name__ == "__main__":
    main()
