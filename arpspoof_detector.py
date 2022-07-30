"""
arpspoof_detector.py

This program monitors the host's arp cache for
duplicate MAC addresses
"""
import os
import sys
import datetime
from time import sleep

LOG_FILE = 'duplicates.log'


def extract_arp_table():
    arp_table = {}
    raw_arp_table = os.popen("arp -a").read()
    table_lines = raw_arp_table.split("\n")
    for line in table_lines:
        line_items = line.split()
        if "dynamic" in line_items:
            ip = line_items[0]
            mac = line_items[1]
            arp_table[ip] = mac
    return arp_table


def log_duplicates(ip, mac):
    with open(LOG_FILE, "a") as log_file:
        timestamp = datetime.datetime.now()
        entry = f"{timestamp} arpspoof_detector: Duplicate MAC found: {mac} with IP {ip}"
        log_file.write(entry)


def detect_duplicate_macs(arp_table):
    macs_seen = []
    for ip in arp_table:
        mac = arp_table[ip]
        if mac in macs_seen:
            print(f"Found duplicate {mac} with {ip}")
            log_duplicates(ip, mac)
        else:
            macs_seen.append(mac)


if __name__ == "__main__":
    while True:
        try:
            print("Detecting...")
            host_arp_table = extract_arp_table()
            detect_duplicate_macs(host_arp_table)
            sleep(5)
        except KeyboardInterrupt:
            print("Exiting program")
            sys.exit(1)






