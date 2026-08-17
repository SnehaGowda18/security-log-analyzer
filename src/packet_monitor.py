from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

from threat_detector import ThreatDetector
from database import create_database, save_alert


detector = ThreatDetector()


def process_packet(packet):

    if IP not in packet:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    protocol = "OTHER"
    source_port = "-"
    destination_port = None

    if TCP in packet:
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    elif ICMP in packet:
        protocol = "ICMP"

    print(
        f"[{timestamp}] "
        f"{protocol} | "
        f"{source_ip}:{source_port} -> "
        f"{destination_ip}:{destination_port}"
    )

    if destination_port is not None:

        alerts = detector.analyze_packet(
            source_ip,
            destination_ip,
            destination_port
        )

        for alert in alerts:

            print("\n" + "=" * 60)
            print("🚨 SECURITY ALERT")
            print("=" * 60)

            print(f"Threat       : {alert['threat_type']}")
            print(f"Source IP    : {alert['source_ip']}")
            print(f"Destination  : {alert['destination_ip']}")
            print(f"Port         : {alert['port']}")
            print(f"Severity     : {alert['severity']}")
            print(f"Message      : {alert['message']}")

            print("=" * 60)

            # Save alert to SQLite database
            save_alert(alert)

            print("✅ Alert saved to database.\n")


def start_monitoring():

    create_database()

    print("=" * 60)
    print("REAL-TIME SECURITY MONITOR")
    print("=" * 60)

    print("Monitoring network traffic...")
    print("Threat detection enabled.")
    print("Database logging enabled.")
    print("Press Ctrl+C to stop.\n")

    sniff(
        prn=process_packet,
        store=False
    )


if __name__ == "__main__":
    start_monitoring()