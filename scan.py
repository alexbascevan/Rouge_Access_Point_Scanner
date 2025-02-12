#!/usr/bin/env python3
import json
import os
import argparse
import time
import struct
from scapy.all import *

# Dictionary to hold AP data, keyed by BSSID.
# Each entry includes: essid, bssid, pwr (list of RSSI values), beacons, data, channel (list),
# mb (maximum bit rate), enc, cipher, auth, and pmf.
ap_data = {}
json_file = "scan_results.json"   # Output JSON file with all data
alert_file = "alert.json"         # Alert file for unwhitelisted/rogue APs

# List to store unique alerts (each will be a full copy of the AP data with an extra "alert_type" field)
alerts = []

def load_whitelist(whitelist_file):
    """Load whitelist from file.
       Each line should be formatted as: ESSID,BSSID
       e.g., MyNetwork,00:11:22:33:44:55"""
    if os.path.exists(whitelist_file):
        with open(whitelist_file, "r") as f:
            # Each whitelist entry is stored as a string "ESSID,BSSID"
            whitelist = { line.strip() for line in f if line.strip() }
        print(f"Loaded whitelist from {whitelist_file}: {whitelist}")
        return whitelist
    else:
        print("No valid whitelist file found. Proceeding without filtering.")
        return set()

def save_to_json():
    """Save AP data to JSON file."""
    with open(json_file, "w") as f:
        json.dump(ap_data, f, indent=4)

def save_alert_data():
    """Save all alert data to JSON file."""
    with open(alert_file, "w") as f:
        json.dump(alerts, f, indent=4)

def parse_rsn(rsn_ie):
    """
    Parse the RSN IE (ID 48) and return a dict with keys:
       enc, cipher, auth, pmf_capable, and pmf_required.
    This is a simplified parser.
    """
    try:
        version = struct.unpack("<H", rsn_ie[0:2])[0]
        if version != 1:
            return {}
        group_cipher = rsn_ie[2:6]  # 4 bytes
        pairwise_count = struct.unpack("<H", rsn_ie[6:8])[0]
        pairwise_list_length = pairwise_count * 4
        pairwise_cipher = rsn_ie[8:12]
        akm_count_offset = 8 + pairwise_list_length
        akm_count = struct.unpack("<H", rsn_ie[akm_count_offset:akm_count_offset+2])[0]
        akm_list_length = akm_count * 4
        akm_suite = rsn_ie[akm_count_offset+2:akm_count_offset+6]  # first AKM suite
        # Check if RSN Capabilities field is present (optional; 2 bytes)
        rsn_capabilities = None
        expected_length_without_cap = akm_count_offset + 2 + akm_list_length
        if len(rsn_ie) >= expected_length_without_cap + 2:
            rsn_capabilities = struct.unpack("<H", rsn_ie[expected_length_without_cap:expected_length_without_cap+2])[0]
        pmf_capable = False
        pmf_required = False
        if rsn_capabilities is not None:
            # Bit 6 (0x0040) indicates PMF capable; bit 7 (0x0080) indicates PMF required.
            if rsn_capabilities & 0x0040:
                pmf_capable = True
            if rsn_capabilities & 0x0080:
                pmf_required = True
        cipher_map = {1:"WEP-40", 2:"TKIP", 4:"CCMP", 5:"WEP-104"}
        akm_map = {1:"802.1X", 2:"PSK"}
        enc = "WPA2"
        cipher = cipher_map.get(pairwise_cipher[3], "Unknown")
        auth = akm_map.get(akm_suite[3], "Unknown")
        return {"enc": enc, "cipher": cipher, "auth": auth, "pmf_capable": pmf_capable, "pmf_required": pmf_required}
    except Exception:
        return {}

def packet_handler(pkt, verbose, whitelist, live_alerts_only):
    """Process sniffed packets and update AP data."""
    if pkt.haslayer(Dot11Beacon):  # Beacon frame
        bssid = pkt[Dot11].addr2
        raw_ssid = pkt[Dot11Elt].info.decode(errors="ignore").strip()
        ssid = raw_ssid if raw_ssid else "<Hidden>"
        display_essid = ssid
        signal_strength = pkt.dBm_AntSignal if hasattr(pkt, "dBm_AntSignal") else None
        encryption = "OPN"  # Default to open
        auth = ""
        cipher = ""
        pmf_str = "No"  # Default PMF info
        channel = None
        supported_rates = []
        extended_rates = []
        rsn_ie = None

        # Loop over Dot11Elt layers to extract IEs.
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:  # SSID
                pass  # Already extracted
            elif elt.ID == 1:  # Supported Rates
                supported_rates += list(elt.info)
            elif elt.ID == 50:  # Extended Supported Rates
                extended_rates += list(elt.info)
            elif elt.ID == 3:  # DS Parameter Set: channel
                channel = elt.info[0]
            elif elt.ID == 48:  # RSN IE
                rsn_ie = elt.info
            elt = elt.payload.getlayer(Dot11Elt)

        if channel is None:
            channel = pkt[Dot11Elt].channel

        # Compute Maximum Bit Rate (MB) from supported rates.
        all_rates = supported_rates + extended_rates
        if all_rates:
            rates_mbps = [rate * 0.5 for rate in all_rates]
            mb = max(rates_mbps)
        else:
            mb = "N/A"

        # Parse RSN IE for encryption and PMF details.
        if rsn_ie:
            rsn_info = parse_rsn(rsn_ie)
            if rsn_info:
                encryption = rsn_info.get("enc", "WPA2")
                cipher = rsn_info.get("cipher", "CCMP")
                auth = rsn_info.get("auth", "PSK")
                if rsn_info.get("pmf_required"):
                    pmf_str = "Required"
                elif rsn_info.get("pmf_capable"):
                    pmf_str = "Capable"
                else:
                    pmf_str = "No"
            else:
                encryption = "WPA2"
                cipher = "CCMP"
                auth = "PSK"
        else:
            encryption = "OPN"
            cipher = ""
            auth = ""
            pmf_str = "No"

        # Update ap_data keyed by BSSID.
        if bssid not in ap_data:
            ap_data[bssid] = {
                "essid": display_essid,
                "bssid": bssid,
                "pwr": [signal_strength] if signal_strength is not None else [],
                "beacons": 1,
                "data": 0,
                "channel": [channel] if channel is not None else [],
                "mb": mb,
                "enc": encryption,
                "cipher": cipher,
                "auth": auth,
                "pmf": pmf_str
            }
        else:
            ap_data[bssid]["beacons"] += 1
            if signal_strength is not None and signal_strength not in ap_data[bssid]["pwr"]:
                ap_data[bssid]["pwr"].append(signal_strength)
            if channel is not None and channel not in ap_data[bssid]["channel"]:
                ap_data[bssid]["channel"].append(channel)

        # --- Whitelist Check (using both ESSID and BSSID) ---
        whitelisted = False
        # The whitelist entries are expected in the format "ESSID,BSSID"
        for entry in whitelist:
            try:
                entry_essid, entry_bssid = entry.split(',')
            except ValueError:
                continue  # Skip improperly formatted lines
            if ssid == entry_essid and bssid == entry_bssid:
                whitelisted = True
                break

        if not whitelisted:
            # Only perform evil twin detection if the network is not hidden.
            if ssid != "<Hidden>":
                # Check for evil twin: same ESSID seen with a different BSSID
                for known_bssid, known_data in ap_data.items():
                    if known_data["essid"] == display_essid and known_bssid != bssid:
                        if not any(alert.get('bssid') == bssid for alert in alerts):
                            alert_data = ap_data[bssid].copy()
                            alert_data["alert_type"] = "Evil Twin Detected"
                            alerts.append(alert_data)
                        if live_alerts_only:
                            print(f"[Evil Twin ALERT] ESSID: {display_essid} BSSID: {bssid} Signal: {signal_strength} Channel: {channel}")
                            print(f"Another BSSID for ESSID {display_essid} detected: {known_bssid}")
            # Create an alert for this not-whitelisted network.
            if not any(alert.get('bssid') == bssid for alert in alerts):
                alert_data = ap_data[bssid].copy()
                alert_data["alert_type"] = "Not Whitelisted"
                alerts.append(alert_data)

        if verbose:
            print(f"[Verbose] Processing Beacon from BSSID: {bssid}, ESSID: {display_essid}, Signal: {signal_strength}, Channel: {channel}")
            print(f"[Verbose] Encryption: {encryption}, Cipher: {cipher}, Auth: {auth}, PMF: {pmf_str}")
            print(f"[Verbose] Max Bit Rate: {mb}, Supported Rates: {supported_rates}")
            print(f"[Verbose] RSN IE: {rsn_ie if rsn_ie else 'None'}")

    elif pkt.haslayer(Dot11) and pkt[Dot11].type == 2:
        # Process data frames (type 2) for counting data frames.
        bssid_data = pkt[Dot11].addr3
        if bssid_data in ap_data:
            ap_data[bssid_data]["data"] += 1

def print_ap_data_table(ap_data, title="All Detected Access Points"):
    """Display the AP data in tabular format.
       Columns: BSSID, Avg PWR, Beacons, #Data, CH, MB, ENC, CIPHER, AUTH, PMF, ESSID"""
    print("=" * 120)
    print(title)
    print("=" * 120)
    header = f"{'BSSID':<20}{'Avg PWR':<10}{'Beacons':<10}{'#Data':<10}{'CH':<5}{'MB':<6}{'ENC':<6}{'CIPHER':<8}{'AUTH':<8}{'PMF':<10}{'ESSID'}"
    print(header)
    print("=" * 120)
    for bssid, data in ap_data.items():
        if data["pwr"]:
            avg_pwr = sum(data["pwr"]) / len(data["pwr"])
        else:
            avg_pwr = None
        avg_pwr_str = f"{avg_pwr:.1f}" if avg_pwr is not None else "N/A"
        ch = ','.join(map(str, data["channel"])) if data["channel"] else "N/A"
        print(f"{data['bssid']:<20}{avg_pwr_str:<10}{data['beacons']:<10}{data['data']:<10}{ch:<5}{data['mb']:<6}{data['enc']:<6}{data['cipher']:<8}{data['auth']:<8}{data['pmf']:<10}{data['essid']}")
    print("=" * 120)

def print_alerts_table(alerts, title="Alerts"):
    """Display the alert data in tabular format.
       It prints the same fields as the AP table plus the Alert Type."""
    print("=" * 140)
    print(title)
    print("=" * 140)
    header = f"{'BSSID':<20}{'Avg PWR':<10}{'Beacons':<10}{'#Data':<10}{'CH':<5}{'MB':<6}{'ENC':<6}{'CIPHER':<8}{'AUTH':<8}{'PMF':<10}{'ESSID':<20}{'Alert'}"
    print(header)
    print("=" * 140)
    for alert in alerts:
        if alert.get("pwr"):
            avg_pwr = sum(alert["pwr"]) / len(alert["pwr"])
            avg_pwr_str = f"{avg_pwr:.1f}"
        else:
            avg_pwr_str = "N/A"
        ch = ','.join(map(str, alert["channel"])) if alert.get("channel") else "N/A"
        alert_type = alert.get("alert_type", "")
        print(f"{alert['bssid']:<20}{avg_pwr_str:<10}{alert['beacons']:<10}{alert['data']:<10}{ch:<5}{alert['mb']:<6}{alert['enc']:<6}{alert['cipher']:<8}{alert['auth']:<8}{alert['pmf']:<10}{alert['essid']:<20}{alert_type}")
    print("=" * 140)

def main():
    parser = argparse.ArgumentParser(
        description="Wi-Fi network scanner that captures and analyzes Wi-Fi networks. "
                    "It supports filtering by whitelist (using ESSID and BSSID), logging detected networks, "
                    "and displaying live updates and alerts. PMF support (Protected Management Frames) is detected "
                    "via the RSN IE.",
        epilog="Examples:\n"
               "  python scan.py wlan0 -c 6 -d 120 -v\n"
               "    Scan for 120 seconds on channel 6 with verbose output.\n"
               "  python scan.py wlan0 -w whitelist.txt\n"
               "    Scan using a whitelist from the specified file (with lines formatted as ESSID,BSSID).\n"
               "  python scan.py wlan0 -L -A\n"
               "    Show live updates with only live alerts (no full AP table)."
    )

    parser.add_argument("iface", help="Network interface to use (e.g., wlan0, mon0)")
    parser.add_argument("-c", "--channel", type=int, help="Channel to set for scanning")
    parser.add_argument("-d", "--duration", type=int, default=60, help="Duration for scanning in seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-w", "--whitelist", help="File containing whitelist entries (ESSID,BSSID per line)")
    parser.add_argument("-L", "--live-updates", action="store_true", help="Enable live update display")
    parser.add_argument("-A", "--live-alerts-only", action="store_true",
                        help="Enable live alert printing only (print only alerts during live updates)")

    args = parser.parse_args()

    # Handle whitelist argument.
    if args.whitelist:
        if os.path.exists(args.whitelist):
            whitelist = load_whitelist(args.whitelist)
        else:
            whitelist = set(args.whitelist.split(","))
            print(f"Using whitelist from argument: {whitelist}")
    else:
        print("No whitelist provided, proceeding with no filtering.")
        whitelist = set()

    if args.channel:
        print(f"Setting channel {args.channel}")
        os.system(f"iw dev {args.iface} set channel {args.channel}")

    print(f"Scanning on interface {args.iface}...\n")
    start_time = time.time()
    update_timeout = 1 if args.live_updates or args.live_alerts_only else 5

    while time.time() - start_time < args.duration:
        sniff(iface=args.iface,
              prn=lambda pkt: packet_handler(pkt, args.verbose, whitelist, args.live_alerts_only),
              store=False,
              timeout=update_timeout)
        save_to_json()  # Save periodically

        if args.live_updates:
            os.system("clear")
            print_ap_data_table(ap_data)
            print_alerts_table(alerts)

        if args.live_alerts_only:
            os.system("clear")
            print_alerts_table(alerts)
       

    if not args.live_updates and not args.live_alerts_only:
        print("\nScan complete.\n")
        save_to_json()  # Final save
        print_ap_data_table(ap_data)
        print_alerts_table(alerts)
        save_alert_data()

if __name__ == "__main__":
    main()
