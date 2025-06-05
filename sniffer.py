from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    print("Packet captured!")
    if IP in packet:
        ip = packet[IP]
        src = ip.src
        dst = ip.dst
        proto = ip.proto
        
        # Protocol name
        if packet.haslayer(TCP):
            proto_name = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif packet.haslayer(UDP):
            proto_name = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        elif packet.haslayer(ICMP):
            proto_name = "ICMP"
            sport = dport = "-"
        else:
            proto_name = f"Other ({proto})"
            sport = dport = "-"
        
        print(f"{proto_name} Packet: {src} → {dst} | Src Port: {sport} | Dst Port: {dport}")
        
        # Payload preview (first 20 bytes)
        if Raw := packet.getlayer('Raw'):
            raw_bytes = Raw.load[:20]
            try:
                raw_text = raw_bytes.decode('utf-8', errors='replace')
            except:
                raw_text = str(raw_bytes)
            print(f"Payload (first 20 bytes): {raw_text}")
        print("-" * 50)

print("Sniffer is running... Press Ctrl+C to stop.")
sniff(prn=packet_callback, count=20, iface="Wi-Fi")


   






