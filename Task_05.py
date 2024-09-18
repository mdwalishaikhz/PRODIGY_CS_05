from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_analysis(packet):
    if IP in packet: 
        ip_layer = packet[IP]
        print(f"\n[+] New Packet: {ip_layer.src} -> {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
        
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
        
        elif ICMP in packet:
            print(f"ICMP Type: {packet[ICMP].type}")

        if packet[IP].payload:
            print(f"Payload: {bytes(packet[IP].payload)[:50]}...") 

def start_sniffing(interface=None):
    print(f"[*] Starting packet capture on {interface if interface else 'all interfaces'}")
    sniff(iface=interface, prn=packet_analysis, store=False)

if _name_ == "_main_":
    interface = None
    start_sniffing(interface)