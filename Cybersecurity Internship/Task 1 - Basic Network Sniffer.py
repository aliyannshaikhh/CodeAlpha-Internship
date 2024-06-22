from scapy.all import *

def sniff_packets(packet):
    if IP in packet: 
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        ttl = packet[IP].ttl
        flags = packet[IP].flags
        frag_offset = packet[IP].frag
        length = len(packet)
        time = packet.time
        
        print(f"Time: {time}, Source IP: {ip_src}, Destination IP: {ip_dst}, Protocol: {proto}, Length: {length}")
        print(f"    TTL: {ttl}, Flags: {flags}, Fragment Offset: {frag_offset}")

        # Additional information based on protocol
        if Ether in packet:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            print(f"    Source MAC: {src_mac}, Destination MAC: {dst_mac}")
        if proto == 6 and TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            seq = packet[TCP].seq
            ack = packet[TCP].ack
            flags = packet[TCP].flags
            payload = packet[TCP].payload
            print(f"    TCP Source Port: {sport}, Destination Port: {dport}")
            print(f"    Sequence Number: {seq}, Acknowledgment Number: {ack}, Flags: {flags}")
            print(f"    Payload: {payload}")
        elif proto == 17 and UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            payload = packet[UDP].payload
            print(f"    UDP Source Port: {sport}, Destination Port: {dport}")
            print(f"    Payload: {payload}")
        elif proto == 1 and ICMP in packet:
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            payload = packet[ICMP].payload
            print(f"    ICMP Type: {icmp_type}, Code: {icmp_code}")
            print(f"    Payload: {payload}")
        else:
            print("     Other protocol or unrecognized packet")

sniff(prn=sniff_packets, store=0)
