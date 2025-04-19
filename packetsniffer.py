from scapy.all import sniff, wrpcap, IP
import signal
import sys

# List to store captured packets
captured_packets = []
pcap_filename = "captured_packets.pcap"

# Callback to process each captured packet
def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        payload = packet[IP].payload

        print(f"Source IP: {src_ip} -> Destination IP: {dst_ip} | Protocol: {protocol}")
        print(f"Payload: {payload}\n")

        # Save the packet
        captured_packets.append(packet)

# Graceful exit: save packets to file when Ctrl+C is pressed
def signal_handler(sig, frame):
    print("\n[!] Stopping packet sniffer...")
    if captured_packets:
        wrpcap(pcap_filename, captured_packets)
        print(f"[+] Captured packets saved to: {pcap_filename}")
    sys.exit(0)

# Bind the signal handler for Ctrl+C
signal.signal(signal.SIGINT, signal_handler)

# Start sniffing
print("=== Packet Sniffer Started ===")
print("Press Ctrl+C to stop sniffing...\n")
sniff(filter="ip", prn=packet_callback, store=False)
