from collections import Counter
from datetime import datetime

# SOC SSH Brute Force Detector v1.0
# Autor: [Pon tu nombre]
# Detecta fuerza bruta SSH y compromisos exitosos en auth.log

with open('auth.log', 'r') as f:
    lineas = f.readlines()

ips_fallidas = []
ips_exitosas = []

for linea in lineas:
    if "Failed password" in linea:
        partes = linea.split()
        ip = partes[-4]
        ips_fallidas.append(ip)
    if "Accepted password" in linea:
        partes = linea.split()
        ip = partes[-4]
        ips_exitosas.append(ip)

print("=== REPORTE DE ACCESOS SSH ===")
print(f"IPs únicas atacando: {len(set(ips_fallidas))}")
print("\nTop 3 atacantes:")
for ip, count in Counter(ips_fallidas).most_common(3):
    print(f"{ip}: {count} intentos")

if ips_exitosas:
    print("\n¡ALERTA! Accesos exitosos detectados:")
    for ip, count in Counter(ips_exitosas).most_common():
        print(f"{ip}: {count} logins exitosos")

timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
nombre_archivo = f"atacantes_{timestamp}.txt"

with open(nombre_archivo, 'w') as f:
    f.write("=== IPs CON INTENTOS FALLIDOS ===\n")
    for ip in set(ips_fallidas):
        f.write(f"{ip}\n")
    f.write("\n=== IPs CON LOGIN EXITOSO ===\n")
    for ip in set(ips_exitosas):
        f.write(f"{ip}\n")

print(f"\nGuardado en {nombre_archivo}")
