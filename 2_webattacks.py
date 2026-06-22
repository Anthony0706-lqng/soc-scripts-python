import re
from collections import Counter
from datetime import datetime

LOG_FILE = 'access.log'
OUTPUT_FILE = f'web_attacks_{datetime.now().strftime("%Y-%m-%d_%H-%M")}.txt'

SQLI_PATTERNS = [r'union.*select', r'or\s+1=1', r'drop\s+table', r"'--", r'admin\'--']
SCAN_PATTERNS = [r'nikto', r'sqlmap', r'nmap', r'acunetix', r'wpscan']
XSS_PATTERNS = [r'<script>', r'javascript:', r'onerror=']

print("=== DETECTOR DE ATAQUES WEB ===")

try:
    with open(LOG_FILE, 'r') as f:
        logs = f.readlines()
except FileNotFoundError:
    print(f"[!] No se encontró {LOG_FILE}. Crea uno de prueba primero.")
    exit()

sqli_hits, scan_hits, xss_hits = [], [], []
ips_sospechosas = []

for line in logs:
    ip_match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
    if not ip_match: continue
    ip = ip_match.group(1)
    
    if any(re.search(p, line, re.IGNORECASE) for p in SQLI_PATTERNS):
        sqli_hits.append(line.strip())
        ips_sospechosas.append(ip)
    if any(re.search(p, line, re.IGNORECASE) for p in SCAN_PATTERNS):
        scan_hits.append(line.strip())
        ips_sospechosas.append(ip)
    if any(re.search(p, line, re.IGNORECASE) for p in XSS_PATTERNS):
        xss_hits.append(line.strip())
        ips_sospechosas.append(ip)

with open(OUTPUT_FILE, 'w') as f:
    f.write("=== REPORTE DE ATAQUES WEB ===\n\n")
    f.write(f"SQL Injection: {len(sqli_hits)} | Scanners: {len(scan_hits)} | XSS: {len(xss_hits)}\n\n")
    if ips_sospechosas:
        f.write("Top 5 IPs atacantes:\n")
        for ip, count in Counter(ips_sospechosas).most_common(5):
            f.write(f"{ip}: {count} hits\n")

print(f"[+] Reporte: {OUTPUT_FILE}")
print(f"[+] SQLi: {len(sqli_hits)} | Scanners: {len(scan_hits)} | XSS: {len(xss_hits)}")

