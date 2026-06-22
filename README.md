# Scripts SOC en Python - Kit Termux para Analistas Junior
[Python](https://img.shields.io/badge/Python-3.11-blue)
[Platform](https://img.shields.io/badge/Platform-Termux%20Android-green)
[MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red)

Suite de 4 scripts Python para detección de amenazas en SOC L1/L2. Desarrollado y testeado 100% en Termux Android sin root.

**Reto técnico superado:** Scapy no funciona en Android por falta de `libpcap`. Se migró el analizador PCAP a `dpkt` para parseo offline.

## Técnicas MITRE ATT&CK Cubiertas

| Script | Técnica MITRE | Ataque Detectado |
| --- | --- | --- |
| `1_ips.py` | **T1110** | SSH Brute Force |
| `2_webattacks.py` | **T1190** | SQLi/XSS en Web Apps |
| `3_windows_events.py` | **T1550.002** | Pass-the-Hash |
| `4_pcap_analyzer.py` | **T1046** | Network Service Scanning |

## Instalación en Termux
```bash
pkg update && pkg install python git
pip install dpkt
git clone https://github.com/Anthony0706-1qng/soc-scripts-python.git
cd soc-scripts-python

python 1_ips.py # Parsea auth.log buscando fuerza bruta
python 2_webattacks.py # Detecta SQLi/XSS en access.log
python 3_windows_events.py # Busca LogonType 9 en security.log
python 4_pcap_analyzer.py # Analiza captura.pcap buscando SYN scans
 
 cada script genera un.txt con timestamp + IOCs listos para escalamiento

¿Por qué termux ? 

Demuestra capacidad de analisis y respuesta en entornos con recursos limitados. No dependes de una SIEM para hacer triage inicial .

AUTOR Anthony Ortiz | Aspirante SOC Analyst | Costa Rica
