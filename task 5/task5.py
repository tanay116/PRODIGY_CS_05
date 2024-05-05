from scapy.all import *


def sniff_packets(iface):
    """
    Sniffs packets on the specified interface and displays basic information.
    """
    print(f"Sniffing packets on interface: {iface}")
    packets = sniff(iface=iface, prn=lambda p: analyze_packet(p))


def analyze_packet(packet):
    """
    Analyzes a captured packet and displays relevant information.
    """
    # Check if packet has layers (e.g., IP, TCP)
    if packet.haslayer(IP):
        # Extract source and destination IP addresses
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Check transport layer protocol (e.g., TCP, UDP)
        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            protocol = "Other"
            src_port = None
            dst_port = None

        # Print basic packet information
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")
        print(f"Protocol: {protocol}, Source Port: {src_port}, Destination Port: {dst_port}")

        # Check if payload data is present
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode("utf-8")  # Assuming UTF-8 encoding
            print(f"Payload: {payload}")

    print("---")  # Separator between packets


# Specify network interface (replace with your actual interface name)
iface = "eth0"

# Start sniffing packets
sniff_packets(iface)
