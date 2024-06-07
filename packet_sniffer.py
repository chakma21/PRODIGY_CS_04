from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        if protocol == 6:  # TCP
            proto = "TCP"
        elif protocol == 17:  # UDP
            proto = "UDP"
        else:
            proto = str(protocol)

        print(f"Source: {ip_src} -> Destination: {ip_dst} | Protocol: {proto}")
        
        # Display payload
        if TCP in packet or UDP in packet:
            payload = packet[TCP].payload if TCP in packet else packet[UDP].payload
            print(f"Payload: {bytes(payload).decode(errors='ignore')}")

def start_sniffing(interface):
    print(f"[*] Starting packet sniffing on {interface}")
    try:
        sniff(iface=interface, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n[*] Stopping packet sniffing.")
        return

if __name__ == "__main__":
    interface = input("Enter the interface to sniff on (e.g., eth0, wlan0): ")
    start_sniffing(interface)
