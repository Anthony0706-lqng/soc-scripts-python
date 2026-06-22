import dpkt
import socket
from collections import Counter
from datetime import datetime

PCAP_FILE = 'capture.pcap'
OUTPUT_FILE = f'red_alerts_{datetime.now().strftime("%Y-%m-%d_%H-%M")}.txt'

print("=== ANALIZADOR PCAP PARA SOC - ANDROID COMPATIBLE ===")

syn_scan = []
dns_queries = []
total_packets = 0

try:
    with open(PCAP_FILE, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            total_packets += 1
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data

                # Detecta SYN scan
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    if tcp.flags == dpkt.tcp.TH_SYN:
                        syn_scan.append(socket.inet_ntoa(ip.src))

                # Detecta DNS queries
                if isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    if udp.dport == 53:
                        try:
                            dns = dpkt.dns.DNS(udp.data)
                            if dns.qr == dpkt.dns.DNS_Q and dns.qd:
                                dns_queries.append(dns.qd[0].name)
                        except:
                            pass
            except:
                continue

except FileNotFoundError:
    print(f"[!] No se encontró {PCAP_FILE}")
    print("[!] Descarga con: curl -L https://wiki.wireshark.org/uploads/27707187aeb30df68e70c8fb9d614981/http.cap -o capture.pcap")
    exit()

with open(OUTPUT_FILE, 'w') as f:
    f.write("=== REPORTE DE TRÁFICO SOSPECHOSO ===\n\n")
    f.write(f"Total paquetes analizados: {total_packets}\n\n")
    
    if syn_scan:
        f.write("Top 5 IPs haciendo SYN Scan - posible nmap:\n")
        for ip, count in Counter(syn_scan).most_common(5):
            f.write(f"{ip}: {count} SYN packets\n")
    else:
        f.write("No se detectaron SYN scans\n")
    
    if dns_queries:
        f.write("\nDominios DNS consultados:\n")
        for domain, count in Counter(dns_queries).most_common(10):
            f.write(f"{domain}: {count} veces\n")
    else:
        f.write("\nNo se detectaron consultas DNS\n")

print(f"[+] Paquetes analizados: {total_packets}")
print(f"[+] IPs con SYN scan: {len(set(syn_scan))}")
print(f"[+] Consultas DNS únicas: {len(set(dns_queries))}")
print(f"[+] Reporte: {OUTPUT_FILE}")
