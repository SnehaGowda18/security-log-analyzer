from collections import defaultdict
from time import time


class ThreatDetector:
    def __init__(self):
        self.port_activity = defaultdict(set)
        self.connection_activity = defaultdict(list)

        # Detection thresholds
        self.port_scan_threshold = 5
        self.connection_threshold = 20
        self.time_window = 10

    def analyze_packet(self, source_ip, destination_ip, destination_port):
        current_time = time()

        alerts = []

        # -------------------------------
        # 1. PORT SCAN DETECTION
        # -------------------------------

        self.port_activity[source_ip].add(destination_port)

        if len(self.port_activity[source_ip]) >= self.port_scan_threshold:
            alerts.append({
                "threat_type": "Port Scan",
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "port": destination_port,
                "severity": "HIGH",
                "message": (
                    f"Possible port scan detected from {source_ip}. "
                    f"{len(self.port_activity[source_ip])} different ports contacted."
                )
            })

            # Reset after alert to prevent continuous alerts
            self.port_activity[source_ip].clear()

        # -------------------------------
        # 2. EXCESSIVE CONNECTION DETECTION
        # -------------------------------

        self.connection_activity[source_ip].append(current_time)

        # Remove old connection timestamps
        self.connection_activity[source_ip] = [
            timestamp
            for timestamp in self.connection_activity[source_ip]
            if current_time - timestamp <= self.time_window
        ]

        connection_count = len(self.connection_activity[source_ip])

        if connection_count >= self.connection_threshold:
            alerts.append({
                "threat_type": "Excessive Connections",
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "port": destination_port,
                "severity": "MEDIUM",
                "message": (
                    f"High connection rate detected from {source_ip}. "
                    f"{connection_count} connections within "
                    f"{self.time_window} seconds."
                )
            })

            self.connection_activity[source_ip].clear()

        return alerts