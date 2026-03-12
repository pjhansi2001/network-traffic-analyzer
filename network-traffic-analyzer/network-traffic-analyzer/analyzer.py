"""
Network Traffic Analyzer
========================
A Python application that analyzes network traffic data,
detects anomalies, and generates visual reports.

Author: Jhansi Pinninti
"""

import csv
import json
import statistics
from datetime import datetime
from collections import defaultdict, Counter


class NetworkTrafficAnalyzer:
    """Analyzes network traffic logs for anomalies and patterns."""

    def __init__(self):
        self.traffic_data = []
        self.anomalies = []
        self.stats = {}

    def load_data(self, filepath):
        """Load traffic data from CSV file."""
        try:
            with open(filepath, 'r') as f:
                reader = csv.DictReader(f)
                self.traffic_data = list(reader)
            print(f"✅ Loaded {len(self.traffic_data)} traffic records from {filepath}")
            return True
        except FileNotFoundError:
            print(f"❌ File not found: {filepath}")
            return False

    def load_sample_data(self):
        """Generate sample network traffic data for demonstration."""
        import random
        protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'FTP', 'SSH']
        flags = ['SYN', 'ACK', 'FIN', 'RST', 'PSH']

        self.traffic_data = []
        for i in range(500):
            # Inject some anomalies (5% of traffic)
            is_anomaly = random.random() < 0.05
            packet_size = random.randint(5000, 9999) if is_anomaly else random.randint(64, 1500)
            port = random.randint(1, 1024) if is_anomaly else random.randint(1024, 65535)

            record = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'src_ip': f"192.168.{random.randint(1,10)}.{random.randint(1,255)}",
                'dst_ip': f"10.0.{random.randint(1,5)}.{random.randint(1,255)}",
                'protocol': random.choice(protocols),
                'src_port': random.randint(1024, 65535),
                'dst_port': port,
                'packet_size': packet_size,
                'flag': random.choice(flags),
                'duration': round(random.uniform(0.001, 5.0), 3)
            }
            self.traffic_data.append(record)

        print(f"✅ Generated {len(self.traffic_data)} sample traffic records")

    def calculate_statistics(self):
        """Calculate descriptive statistics on traffic data."""
        if not self.traffic_data:
            print("❌ No data loaded. Call load_data() or load_sample_data() first.")
            return {}

        packet_sizes = [int(r['packet_size']) for r in self.traffic_data]
        durations = [float(r['duration']) for r in self.traffic_data]

        self.stats = {
            'total_records': len(self.traffic_data),
            'packet_size': {
                'mean': round(statistics.mean(packet_sizes), 2),
                'median': statistics.median(packet_sizes),
                'stdev': round(statistics.stdev(packet_sizes), 2),
                'min': min(packet_sizes),
                'max': max(packet_sizes)
            },
            'duration': {
                'mean': round(statistics.mean(durations), 4),
                'median': round(statistics.median(durations), 4),
                'stdev': round(statistics.stdev(durations), 4)
            },
            'protocol_distribution': dict(Counter(r['protocol'] for r in self.traffic_data)),
            'flag_distribution': dict(Counter(r['flag'] for r in self.traffic_data)),
            'top_source_ips': self._get_top_ips('src_ip', 5),
            'top_dest_ips': self._get_top_ips('dst_ip', 5)
        }

        print(f"\n📊 Traffic Statistics:")
        print(f"   Total Records    : {self.stats['total_records']}")
        print(f"   Avg Packet Size  : {self.stats['packet_size']['mean']} bytes")
        print(f"   Std Dev (size)   : {self.stats['packet_size']['stdev']} bytes")
        print(f"   Avg Duration     : {self.stats['duration']['mean']} sec")
        print(f"   Protocol Mix     : {self.stats['protocol_distribution']}")

        return self.stats

    def _get_top_ips(self, field, n):
        """Get top N IP addresses by frequency."""
        counter = Counter(r[field] for r in self.traffic_data)
        return dict(counter.most_common(n))

    def detect_anomalies(self):
        """
        Detect network anomalies using statistical threshold method.
        Flags records where packet_size > mean + 2*stdev (Z-score method).
        """
        if not self.stats:
            self.calculate_statistics()

        mean_size = self.stats['packet_size']['mean']
        stdev_size = self.stats['packet_size']['stdev']
        threshold = mean_size + (2 * stdev_size)

        self.anomalies = []
        port_frequency = Counter(int(r['dst_port']) for r in self.traffic_data)

        for record in self.traffic_data:
            packet_size = int(record['packet_size'])
            dst_port = int(record['dst_port'])
            reasons = []

            # Rule 1: Unusually large packet size (Z-score > 2)
            if packet_size > threshold:
                z_score = round((packet_size - mean_size) / stdev_size, 2)
                reasons.append(f"Large packet size (z-score: {z_score})")

            # Rule 2: Suspicious destination port (well-known ports accessed unusually)
            if dst_port < 1024 and port_frequency[dst_port] > 10:
                reasons.append(f"High-frequency access to privileged port {dst_port}")

            # Rule 3: RST flood detection
            if record['flag'] == 'RST' and packet_size > mean_size:
                reasons.append("RST flag with above-average packet size")

            if reasons:
                anomaly = {**record, 'anomaly_reasons': reasons, 'risk_score': len(reasons)}
                self.anomalies.append(anomaly)

        detection_rate = round((len(self.anomalies) / len(self.traffic_data)) * 100, 2)
        print(f"\n🚨 Anomaly Detection Results:")
        print(f"   Total Anomalies  : {len(self.anomalies)}")
        print(f"   Detection Rate   : {detection_rate}%")
        print(f"   Detection Method : Z-Score + Rule-Based Analysis")

        return self.anomalies

    def generate_report(self, output_file='traffic_report.json'):
        """Generate a comprehensive JSON report."""
        if not self.anomalies:
            self.detect_anomalies()

        report = {
            'report_generated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'summary': {
                'total_records_analyzed': len(self.traffic_data),
                'anomalies_detected': len(self.anomalies),
                'detection_rate_percent': round((len(self.anomalies) / len(self.traffic_data)) * 100, 2),
                'analysis_method': 'Z-Score Statistical Analysis + Rule-Based Detection'
            },
            'statistics': self.stats,
            'top_anomalies': sorted(self.anomalies, key=lambda x: x['risk_score'], reverse=True)[:10]
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        print(f"\n✅ Report saved to {output_file}")
        return report

    def print_dashboard(self):
        """Print a text-based analytics dashboard."""
        if not self.stats:
            self.calculate_statistics()

        print("\n" + "="*60)
        print("       NETWORK TRAFFIC ANALYSIS DASHBOARD")
        print("="*60)
        print(f"\n📈 TRAFFIC OVERVIEW")
        print(f"   Records Analyzed : {self.stats['total_records']:,}")
        print(f"   Anomalies Found  : {len(self.anomalies)}")
        print(f"\n📦 PACKET SIZE DISTRIBUTION")
        print(f"   Mean   : {self.stats['packet_size']['mean']:>8} bytes")
        print(f"   Median : {self.stats['packet_size']['median']:>8} bytes")
        print(f"   StdDev : {self.stats['packet_size']['stdev']:>8} bytes")
        print(f"   Min    : {self.stats['packet_size']['min']:>8} bytes")
        print(f"   Max    : {self.stats['packet_size']['max']:>8} bytes")
        print(f"\n🌐 PROTOCOL DISTRIBUTION")
        for proto, count in sorted(self.stats['protocol_distribution'].items(),
                                    key=lambda x: x[1], reverse=True):
            bar = "█" * (count // 10)
            print(f"   {proto:<8} {count:>4}  {bar}")
        print(f"\n🔝 TOP SOURCE IPs")
        for ip, count in self.stats['top_source_ips'].items():
            print(f"   {ip:<20} {count} packets")
        print("\n" + "="*60)


def main():
    """Main entry point — runs the full analysis pipeline."""
    print("🔍 Network Traffic Analyzer")
    print("   Author: Jhansi Pinninti\n")

    analyzer = NetworkTrafficAnalyzer()

    # Load sample data (replace with analyzer.load_data('your_file.csv') for real data)
    analyzer.load_sample_data()

    # Calculate statistics
    analyzer.calculate_statistics()

    # Detect anomalies
    analyzer.detect_anomalies()

    # Print dashboard
    analyzer.print_dashboard()

    # Generate report
    analyzer.generate_report('network_traffic_report.json')

    print("\n✅ Analysis complete!")


if __name__ == "__main__":
    main()
