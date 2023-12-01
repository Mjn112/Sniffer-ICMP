import scapy.all as scapy


def sniffing(interface):
    scapy.sniff(iface=interface, store=False,
                prn=process_packet, filter='icmp')


def process_packet(packet):
    if packet.haslayer(scapy.ICMP):
        print("Capturado pacote ICMP")
        packet.show()


sniffing('Wi-Fi')
