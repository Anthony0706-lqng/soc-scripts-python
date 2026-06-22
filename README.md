# SOC Scripts Python - Junior Analyst Toolkit

Scripts de Python para tareas de SOC Nivel 1, desarrollados en Termux Android.

## 1_ips.py - SSH Brute Force Detector + Breach Alert

**Qué hace:**
1. Parsea `auth.log` buscando fuerza bruta SSH
2. Detecta `Accepted password` = compromiso confirmado
3. Exporta IOCs con timestamp a `.txt`
4. Genera alerta automática si detecta login exitoso

**Uso:**
```bash
python 1_ips.py

=== REPORTE DE ACCESOS SSH ===
IPs únicas atacando: 2

Top 3 atacantes:
45.33.12.5: 4 intentos
192.168.1.10: 3 intentos


