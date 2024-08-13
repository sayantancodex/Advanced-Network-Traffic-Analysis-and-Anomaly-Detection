import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from ipaddress import ip_address
from datetime import datetime

# Read the pcap file
packets = rdpcap('scan.pcap')

# Extract relevant packet information
packet_data = []
for packet in packets:
    if IP in packet:
        packet_info = {
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'protocol': packet[IP].proto,
            'timestamp': packet.time
        }
        if TCP in packet:
            packet_info.update({
                'src_port': packet[TCP].sport,
                'dst_port': packet[TCP].dport,
                'protocol_type': 'TCP'
            })
        elif UDP in packet:
            packet_info.update({
                'src_port': packet[UDP].sport,
                'dst_port': packet[UDP].dport,
                'protocol_type': 'UDP'
            })
        packet_data.append(packet_info)

# Create a DataFrame
df = pd.DataFrame(packet_data)

# Save DataFrame to CSV to verify the contents
df.to_csv('packets_analysis.csv', index=False)

# Display a sample of both TCP and UDP packets
print("Sample TCP packets:")
print(df[df['protocol_type'] == 'TCP'].head())

print("\nSample UDP packets:")
print(df[df['protocol_type'] == 'UDP'].head())

# Verify the number of TCP and UDP packets
tcp_packets = df[df['protocol_type'] == 'TCP']
udp_packets = df[df['protocol_type'] == 'UDP']
print(f"Number of TCP packets: {len(tcp_packets)}")
print(f"Number of UDP packets: {len(udp_packets)}")

# Convert timestamp to float and then to datetime
df['timestamp'] = df['timestamp'].astype(float)
df['timestamp'] = df['timestamp'].apply(lambda x: datetime.utcfromtimestamp(x))

# Top Talkers
top_talkers_src = df['src_ip'].value_counts().head(20)
top_talkers_dst = df['dst_ip'].value_counts().head(20)

# Print Top Talkers
print("\nTop 20 Source IPs:")
print(top_talkers_src)

print("\nTop 20 Destination IPs:")
print(top_talkers_dst)

# Protocol Distribution
protocol_distribution = df['protocol_type'].value_counts()

# Traffic Volume Over Time
traffic_over_time = df.set_index('timestamp').resample('1T').size()

# Visualization
plt.figure(figsize=(20, 6))
top_talkers_src.plot(kind='bar', title='Top 20 Source IPs')
plt.xlabel('Source IP')
plt.ylabel('Packet Count')
plt.show()

plt.figure(figsize=(20, 6))
top_talkers_dst.plot(kind='bar', title='Top 20 Destination IPs')
plt.xlabel('Destination IP')
plt.ylabel('Packet Count')
plt.show()

plt.figure(figsize=(20, 6))
protocol_distribution.plot(kind='bar', title='Protocol Distribution')
plt.xlabel('Protocol')
plt.ylabel('Count')
plt.show()

plt.figure(figsize=(20, 6))
traffic_over_time.plot(title='Traffic Volume Over Time')
plt.xlabel('Time')
plt.ylabel('Number of Packets')
plt.show()

# Use the most active IPs as known malicious IPs
known_malicious_ips = list(top_talkers_src.index) + list(top_talkers_dst.index)

def detect_known_threats(df):
    threats = df[df['src_ip'].isin(known_malicious_ips) | df['dst_ip'].isin(known_malicious_ips)]
    return threats

detected_threats = detect_known_threats(df)
print("Detected threats:\n", detected_threats)

# Prepare data for anomaly detection
df['timestamp'] = df['timestamp'].apply(lambda x: int(x.timestamp()))  # Convert to Unix timestamp
df['src_ip_num'] = df['src_ip'].apply(lambda x: int(ip_address(x)))
df['dst_ip_num'] = df['dst_ip'].apply(lambda x: int(ip_address(x)))
feature_columns = ['src_ip_num', 'dst_ip_num', 'src_port', 'dst_port', 'timestamp']

# Drop rows with NaN values
df = df.dropna(subset=feature_columns)

# Train Isolation Forest model
model = IsolationForest(contamination=0.01)
model.fit(df[feature_columns])

# Predict anomalies
df['anomaly'] = model.predict(df[feature_columns])
anomalies = df[df['anomaly'] == -1]
print("Detected anomalies:\n", anomalies)

# Save anomalies to CSV
anomalies.to_csv('anomalies.csv', index=False)

# Visualization of anomalies
plt.figure(figsize=(20, 6))
anomalies.set_index('timestamp')['src_ip'].value_counts().plot(kind='bar', title='Probable anomalous Source IPs')
plt.xlabel('Source IP')
plt.ylabel('Count')
plt.show()

plt.figure(figsize=(20, 6))
anomalies.set_index('timestamp')['dst_ip'].value_counts().plot(kind='bar', title='Probable anomalous Destination IPs')
plt.xlabel('Destination IP')
plt.ylabel('Count')
plt.show()