
from scapy.all import sniff

# Define firewall rules
firewall_rules = {
    "block_ips": ["192.168.1.100", "10.0.0.5"],
    "block_ports": [80, 443]  # Block HTTP and HTTPS
}

def apply_firewall_rules(packet):
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
        if src_ip in firewall_rules["block_ips"] or dst_ip in firewall_rules["block_ips"]:
            print(f"[BLOCKED] IP: {src_ip} -> {dst_ip}")
            return False
    if packet.haslayer("TCP"):
        sport = packet["TCP"].sport
        dport = packet["TCP"].dport
        if sport in firewall_rules["block_ports"] or dport in firewall_rules["block_ports"]:
            print(f"[BLOCKED] Port: {sport} -> {dport}")
            return False
    print(f"[ALLOWED] {packet.summary()}")
    return True

def packet_callback(packet):
    apply_firewall_rules(packet)

# Sniff network packets and apply firewall rules (requires admin/sudo)
sniff(prn=packet_callback, store=0)
