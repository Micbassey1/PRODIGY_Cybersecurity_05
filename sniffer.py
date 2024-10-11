from scapy.all import sniff, IP, TCP, UDP

# Packet processing function
def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        proto = 'Unknown'
        if packet.haslayer(TCP):
            proto = 'TCP'
        elif packet.haslayer(UDP):
            proto = 'UDP'
        
        print(f'Source IP: {ip_layer.src}')
        print(f'Destination IP: {ip_layer.dst}')
        print(f'Protocol: {proto}')
        
        if proto == 'TCP' or proto == 'UDP':
            print(f'Payload: {bytes(packet[proto].payload)}')

# Start sniffing
sniff(prn=process_packet, filter="ip", store=0)

