from datetime import datetime
from collections import Counter

LOG_FILE = 'security.log'
OUTPUT_FILE = f'windows_events_{datetime.now().strftime("%Y-%m-%d_%H-%M")}.txt'

print("=== DETECTOR PASS-THE-HASH / LOGON SOSPECHOSO ===")

with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()

matches = []
# Cada evento termina en </Event>
for event in content.split('</Event>'):
    # Busca las 3 condiciones: 4624 + LogonType 9 + saca IP y usuario
    if '<EventID>4624</EventID>' in event and 'Name="LogonType">9<' in event:
        ip = "Unknown"
        user = "Unknown"
        
        # Extraer IP
        start_ip = event.find('Name="IpAddress">') + 17
        if start_ip > 16:
            end_ip = event.find('<', start_ip)
            ip = event[start_ip:end_ip]
        
        # Extraer Usuario
        start_user = event.find('Name="Account Name">') + 20
        if start_user > 19:
            end_user = event.find('<', start_user)
            user = event[start_user:end_user]
        
        matches.append((ip, user))

with open(OUTPUT_FILE, 'w') as f:
    f.write("=== REPORTE WINDOWS LOGON SOSPECHOSO ===\n\n")
    f.write("LogonType 9 = NewCredentials. Indicador de Pass-the-Hash, RunAs, psexec.\n\n")
    if matches:
        f.write("Top IPs / Usuarios:\n")
        for ip, user in Counter(matches).most_common(10):
            f.write(f"{ip} -> {user}: {matches.count((ip,user))} eventos\n")
    else:
        f.write("No se detectaron eventos LogonType 9\n")

print(f"[+] Eventos LogonType 9 detectados: {len(matches)}")
print(f"[+] Reporte: {OUTPUT_FILE}")
