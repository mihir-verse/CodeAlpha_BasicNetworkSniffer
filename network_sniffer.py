import csv
import logging
import os
from collections import Counter
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP


# Project configuration
OUTPUT_DIR = "reports"
PACKET_LIMIT = 20

os.makedirs(OUTPUT_DIR, exist_ok=True)

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

CSV_FILE = os.path.join(
    OUTPUT_DIR, f"packet_report_{timestamp}.csv"
)

LOG_FILE = os.path.join(OUTPUT_DIR, "sniffer.log")


# Configure logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    encoding="utf-8"
)


# Statistics
protocol_counts = Counter()
captured_count = 0


def identify_protocol(packet):
    """Identify the network protocol."""

    if TCP in packet:
        return "TCP"
    elif UDP in packet:
        return "UDP"
    elif ICMP in packet:
        return "ICMP"
    else:
        return "Other"


def process_packet(packet):
    """Analyze an IP packet and save its metadata."""

    global captured_count

    if IP not in packet:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    protocol = identify_protocol(packet)

    packet_time = datetime.now().astimezone().isoformat(
        timespec="seconds"
    )

    captured_count += 1
    protocol_counts[protocol] += 1

    print("-" * 55)
    print(f"Timestamp      : {packet_time}")
    print(f"Source IP      : {source_ip}")
    print(f"Destination IP : {destination_ip}")
    print(f"Protocol       : {protocol}")
    print(f"Packet Size    : {len(packet)} bytes")

    with open(
        CSV_FILE,
        "a",
        newline="",
        encoding="utf-8"
    ) as csvfile:

        writer = csv.writer(csvfile)

        writer.writerow([
            packet_time,
            source_ip,
            destination_ip,
            protocol,
            len(packet)
        ])

    logging.info(
        "Captured packet: %s -> %s, protocol=%s",
        source_ip,
        destination_ip,
        protocol
    )


def main():
    """Start the authorized network capture."""

    print("=" * 55)
    print("       CODEALPHA NETWORK SNIFFER")
    print("=" * 55)
    print(f"Packet limit : {PACKET_LIMIT}")
    print(f"CSV report   : {CSV_FILE}")
    print("Monitoring IP packet metadata only.")
    print("Press CTRL+C to stop early.")
    print()

    try:
        # Create the CSV report with column headers.
        with open(
            CSV_FILE,
            "w",
            newline="",
            encoding="utf-8"
        ) as csvfile:

            writer = csv.writer(csvfile)
            writer.writerow([
                "Timestamp",
                "Source IP",
                "Destination IP",
                "Protocol",
                "Packet Size (bytes)"
            ])

        logging.info("Network sniffer started.")

        # Capture a limited number of packets.
        sniff(
            filter="ip",
            prn=process_packet,
            store=False,
            count=PACKET_LIMIT
        )

    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
        logging.info("Capture stopped by user.")

    except PermissionError:
        print("\nPermission denied.")
        print("Check capture permissions and Npcap.")
        logging.exception("Permission error.")

    except Exception as error:
        print(f"\nAn error occurred: {error}")
        logging.exception("Capture failed.")

    finally:
        print("\n" + "=" * 55)
        print("             CAPTURE SUMMARY")
        print("=" * 55)
        print(f"Total IP packets processed: {captured_count}")

        for protocol, count in protocol_counts.items():
            print(f"{protocol}: {count}")

        print(f"\nCSV report: {CSV_FILE}")
        print(f"Log file  : {LOG_FILE}")

        logging.info(
            "Capture finished. Processed=%d",
            captured_count
        )


if __name__ == "__main__":
    main()