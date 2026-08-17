from threat_detector import ThreatDetector
from database import create_database, save_alert


create_database()

detector = ThreatDetector()

source_ip = "192.168.1.100"
destination_ip = "192.168.1.10"

ports = [21, 22, 23, 25, 80]

for port in ports:

    alerts = detector.analyze_packet(
        source_ip,
        destination_ip,
        port
    )

    for alert in alerts:

        print("\n🚨 SECURITY ALERT")
        print("=" * 50)

        print(f"Threat: {alert['threat_type']}")
        print(f"Source IP: {alert['source_ip']}")
        print(f"Destination IP: {alert['destination_ip']}")
        print(f"Port: {alert['port']}")
        print(f"Severity: {alert['severity']}")
        print(f"Message: {alert['message']}")

        save_alert(alert)

        print("✅ Alert saved to database.")