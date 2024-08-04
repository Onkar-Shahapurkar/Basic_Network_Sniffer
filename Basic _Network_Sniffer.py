from scapy.all import sniff, IP, TCP, UDP, conf
import sys

def packet_handler(packet):
    try:
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            print(f"Source IP: {ip_layer.src}")
            print(f"Destination IP: {ip_layer.dst}")

            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                print(f"Source Port: {tcp_layer.sport}")
                print(f"Destination Port: {tcp_layer.dport}")
                print("Protocol: TCP")
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                print(f"Source Port: {udp_layer.sport}")
                print(f"Destination Port: {udp_layer.dport}")
                print("Protocol: UDP")

            print(f"Payload: {bytes(packet[IP].payload)}")
            print("\n")
    except Exception as e:
        print(f"Error processing packet: {e}")


def start_sniffing(interface, packet_count):
    try:
        sniff(iface=interface, count=packet_count, prn=packet_handler)
    except Exception as e:
        print(f"Error starting sniffer: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # List available interfaces
    print("Available network interfaces:")
    for iface in conf.ifaces:
        print(f"{iface} - {conf.ifaces[iface].description}")

    interface = input("Enter the network interface name or number: ")
    packet_count = int(input("Enter the number of packets to capture: "))

    # Run the sniffer
    start_sniffing(interface, packet_count)
