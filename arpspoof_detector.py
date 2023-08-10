"""
ARP Spoof Detector - Final Project
    Tool to check if an ARP spoofing attack is in progress
"""
import datetime
import os
import time

""" Global Variables """

LOG_FILE = 'arpspoof.log'

""" Functions """


def extract_arp_table():
    """ Project Task 1: ARP Table Extraction
        1. Execute the "arp -a" command
        2. Capture the output and store variable
        3. Parse the output in the variable
        4. Store the IP address to MAC mapping into a dictionary
    """

    # Dictionary to hold the IP-to-MAC mapping
    ip_mac_map = {}

    # Execute the system command and store it in a variable
    command_output = os.popen("arp -a").read()
    # Split the output of the command into separate lines
    output_lines = command_output.splitlines()

    # Process each line in the command's output
    for line in output_lines:
        # Split the line by whitespace
        line_split = line.split()

        # Process only the entries in the list that contain a 'dynamic' type
        if 'dynamic' in line_split:
            # Pull out the key fields by referring to the corresponding index
            ip_address = line_split[0]
            mac_address = line_split[1]

            # Add the IP Address to MAC mapping to the dictionary
            ip_mac_map[ip_address] = mac_address

    return ip_mac_map


def id_duplicate_macs(arp_table):
    """ Project Task 2: Identifying MAC Address Duplication """

    duplicate = None
    macs_seen = []

    for ip in arp_table.keys():
        mac = arp_table[ip]
        if mac in macs_seen:
            print(f"*** Found a duplicate MAC: {mac}")
            duplicate = mac
            break
        else:
            macs_seen.append(mac)
    return duplicate


def log_entry(message):
    """ Project Task 3: Logging Events """

    timestamp = datetime.datetime.now()  # Format looks like: 2023-04-23 14:28:37.287318

    with open(LOG_FILE, 'a') as arp_log:
        arp_log.write(f"{timestamp} - arpspoof.py: {message}\n")


def main():
    try:
        # Use an infinite loop to continuously check for an attack
        while True:
            print("Detecting arpspoof attacks...")
            arp_map = extract_arp_table()
            duplicate_mac = id_duplicate_macs(arp_map)
            if duplicate_mac:
                log_entry(f"Duplicate MAC address found: {duplicate_mac}")
            time.sleep(1)

    # Catch Ctrl-C or the stop button in the IDE
    except KeyboardInterrupt:
        print("Stopping arpspoof attack detection")


# Check if script is directly executed or is being imported
if __name__ == '__main__':
    main()



