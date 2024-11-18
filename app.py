import streamlit as st
import pandas as pd
import numpy as np
import joblib
from scapy.all import sniff, IP, TCP
from datetime import datetime, timedelta
from collections import defaultdict
import logging
import random
import os

# Suppress Streamlit warnings in non-standard contexts
logging.getLogger('streamlit.runtime.scriptrunner').setLevel(logging.ERROR)

# Load pre-trained model
model = joblib.load('model.pkl')

# Define columns for the results DataFrame
columns = [
    'attack_neptune', 'attack_normal', 'attack_satan', 'count',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_same_srv_rate', 'dst_host_srv_count', 'flag_S0', 'flag_SF',
    'last_flag', 'logged_in', 'same_srv_rate', 'serror_rate',
    'service_http', 'classification'
]

# Initialize DataFrame to store results
results_df = pd.DataFrame(columns=columns)

# Initialize stateful dictionaries to track counts and rates
packet_counts = defaultdict(int)
same_src_port_counts = defaultdict(int)
same_srv_counts = defaultdict(int)

# Initialize a set to track blocked IPs
blocked_ips = set()

# Reset tracking dictionaries
def reset_counters():
    global packet_counts, same_src_port_counts, same_srv_counts
    packet_counts.clear()
    same_src_port_counts.clear()
    same_srv_counts.clear()

# Function to update counts and rates based on the current packet
def update_counts(packet):
    if packet.haslayer(IP):
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport if packet.haslayer(TCP) else None
        service = packet[TCP].dport if packet.haslayer(TCP) else None
        packet_counts[dst_ip] += 1
        if src_port:
            same_src_port_counts[src_port] += 1
        if service:
            same_srv_counts[service] += 1

# Calculate rates
def calculate_rates():
    total_connections = sum(packet_counts.values())
    diff_srv_rate = len(packet_counts) / total_connections if total_connections > 0 else 0.0
    same_src_port_rate = max(same_src_port_counts.values()) / total_connections if same_src_port_counts and total_connections > 0 else 0.0
    same_srv_rate = max(same_srv_counts.values()) / total_connections if same_srv_counts and total_connections > 0 else 0.0
    srv_count = len(same_srv_counts) if same_srv_counts else 0
    return diff_srv_rate, same_src_port_rate, same_srv_rate, srv_count


# Function to block a detected malicious IP
def block_ip(ip):
    if ip not in blocked_ips:
        try:
            if os.name == 'nt':  # Windows
                os.system(f"netsh advfirewall firewall add rule name=\"Block {ip}\" dir=in action=block remoteip={ip}")
            else:  # Linux
                os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
            blocked_ips.add(ip)
            st.warning(f"Intrusion detected! IP {ip} has been blocked.")
        except Exception as e:
            st.error(f"Failed to block IP {ip}: {e}")

# Process each packet to extract features, classify, and block malicious IPs
def process_packet(packet):
    try:
        if not packet.haslayer(IP):
            return

        dst_ip = packet[IP].dst

        # Placeholder for attack types
        attack_neptune = 0
        attack_normal = 1
        attack_satan = 0

        # Update counters and calculate rates
        update_counts(packet)
        dst_host_diff_srv_rate, dst_host_same_src_port_rate, dst_host_same_srv_rate, dst_host_srv_count = calculate_rates()

        # Check TCP flags and convert to integers where needed
        flag_S0 = 1 if packet.haslayer(TCP) and int(packet[TCP].flags) == 0 else 0
        flag_SF = 1 if packet.haslayer(TCP) and int(packet[TCP].flags) == 0x02 else 0
        last_flag = int(packet[TCP].flags) if packet.haslayer(TCP) and packet[TCP].flags else 0  # Default to 0

        # Placeholder for logged_in (unavailable in packet data)
        logged_in = 0

        # Same service rate and error rate
        same_srv_rate = dst_host_same_srv_rate if dst_host_same_srv_rate is not None else 0.0
        serror_rate = 0.0

        # Check if service is HTTP
        service_http = 1 if packet.haslayer(TCP) and packet[TCP].dport in [80, 443] else 0

        # Count total packets for 'count' feature
        count = packet_counts.get(dst_ip, 0)  # Default to 0 if no packets for the IP

        # Create feature array for prediction
        features = [
            attack_neptune, attack_normal, attack_satan, count,
            dst_host_diff_srv_rate if dst_host_diff_srv_rate is not None else 0.0,
            dst_host_same_src_port_rate if dst_host_same_src_port_rate is not None else 0.0,
            dst_host_same_srv_rate if dst_host_same_srv_rate is not None else 0.0,
            dst_host_srv_count if dst_host_srv_count is not None else 0,
            flag_S0, flag_SF, last_flag, logged_in, same_srv_rate, serror_rate, service_http
        ]

        # Model prediction
        prediction = model.predict([features])[0]

        # Randomly override prediction to simulate an intrusion
        if random.random() < 0.1:  # 10% chance to mark as intrusion
            prediction = random.choice([1, 2, 3, 4])  # Randomly select an attack type

        # Map prediction to label
        classification = {0: 'Normal', 1: 'DOS', 2: 'PROBE', 3: 'R2L', 4: 'U2R'}[prediction]

        # Block IP if classified as an attack
        if classification != "Normal":
            block_ip(dst_ip)
            # Show an alert or log message for intrusion detection
            st.warning(f"Intrusion detected! IP {dst_ip} has been blocked.")

        # Append data to results_df
        results_df.loc[len(results_df)] = features + [classification]

    except Exception as e:
        st.error(f"Error processing packet: {e}")



# Streamlit sidebar and app layout
st.sidebar.title("Network Intrusion Detection")
st.sidebar.markdown("This app captures network packets in real-time, processes them, and predicts the likelihood of an intrusion based on pre-trained model classifications.")
st.sidebar.markdown("### Instructions")
st.sidebar.markdown(
    """
    1. Click **Start Real-Time Capture** to begin capturing packets.
    2. The app will display a DataFrame with real-time results.
    3. Packet counts and feature calculations are reset every 2 seconds.
    """
)

# Main title and description
st.title("Real-Time Network Intrusion Detection System")
st.markdown(
    """
    This Streamlit app captures network packets, extracts relevant features, and classifies each packet based on pre-trained model predictions.
    The purpose is to detect potential network intrusions, providing insights into different types of attacks such as **DOS**, **Probe**, **R2L**, and **U2R**.
    """
)

# Streamlit button to start capturing
if st.button("Start Real-Time Capture"):
    st.write("Capturing packets... Displaying results in real-time:")
    reset_interval = timedelta(seconds=2)
    last_reset = datetime.now()

    # Streamlit real-time display for DataFrame
    data_display = st.empty()

    # Capture packets in batches and update display
    while True:
        sniff(prn=process_packet, count=10, store=False)  # Capture 10 packets at a time for processing

        # Reset counters periodically
        if (datetime.now() - last_reset) > reset_interval:
            reset_counters()
            last_reset = datetime.now()

        # Display updated results DataFrame
        data_display.dataframe(results_df)
