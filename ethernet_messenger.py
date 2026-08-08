#!/usr/bin/env python3
"""
Ethernet Messenger
-------------------
Educatieve GUI-tool voor het versturen en ontvangen van ruwe Ethernet
frames op basis van MAC-adressen. Bedoeld voor CCNA-onderwijs (MBO ICT).

Vereist root-rechten (of CAP_NET_RAW/CAP_NET_ADMIN via setcap) omdat er
raw sockets worden gebruikt om Layer 2 Ethernet frames te bouwen,
versturen en te sniffen.

Alleen bedoeld voor gecontroleerde lab-/testomgevingen (bijv. Cisco CML
of een geïsoleerd VLAN), niet voor productienetwerken.
"""

import os
import sys
import threading
import time

from PyQt6.QtCore import Qt, pyqtSignal, QObject
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QFormLayout,
    QLabel,
    QLineEdit,
    QComboBox,
    QPushButton,
    QCheckBox,
    QTextEdit,
    QMessageBox,
    QGroupBox,
)

try:
    from scapy.all import Ether, sendp, sniff, get_if_list, get_if_hwaddr, conf
except ImportError:
    print(
        "Scapy is niet geïnstalleerd. Installeer het met:\n"
        "  sudo pip install --break-system-packages scapy\n"
        "of gebruik een virtuele omgeving (zie README.md)."
    )
    sys.exit(1)


DEFAULT_ETHERTYPE = 0x88B5  # gereserveerd voor experimenteel/onderwijsgebruik
BPF_ETHERTYPE_FILTER = f"ether proto {DEFAULT_ETHERTYPE:#06x}"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def is_loopback_interface(iface_name):
    """Bepaalt of een interface de loopback-interface is."""
    if iface_name == "lo" or iface_name.startswith("lo:"):
        return True
    try:
        with open(f"/sys/class/net/{iface_name}/flags") as f:
            IFF_LOOPBACK = 0x8
            return int(f.read().strip(), 16) & IFF_LOOPBACK != 0
    except Exception:
        return False


def is_physical_interface(iface_name):
    """
    Bepaalt of een interface een fysieke netwerkkaart is (bijv. een
    Ethernet- of wifi-adapter), in tegenstelling tot virtuele interfaces
    zoals bridges, veth-paren, docker0, tun/tap, enz.
    """
    return os.path.exists(f"/sys/class/net/{iface_name}/device")


def classify_mac(mac):
    """Classificeert een MAC-adres als broadcast, multicast of unicast."""
    if mac.lower() == BROADCAST_MAC:
        return "broadcast"
    try:
        eerste_octet = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return "onbekend"
    # I/G-bit (bit 0 van het eerste octet): 1 = multicast, 0 = unicast
    if eerste_octet & 0x01:
        return "multicast"
    return "unicast"


def get_readable_interfaces():
    """
    Geeft een lijst van (leesbare_naam, scapy_interface_naam) terug voor
    alle beschikbare netwerkinterfaces, met uitzondering van de
    loopback-interface.
    """
    interfaces = []
    try:
        for iface_name in get_if_list():
            if is_loopback_interface(iface_name):
                continue
            readable = iface_name
            try:
                iface_obj = conf.ifaces.dev_from_name(iface_name)
                if getattr(iface_obj, "description", None):
                    readable = f"{iface_obj.description} ({iface_name})"
                elif getattr(iface_obj, "name", None):
                    readable = f"{iface_obj.name} ({iface_name})"
            except Exception:
                pass
            interfaces.append((readable, iface_name))
    except Exception:
        pass
    return interfaces


class SnifferSignals(QObject):
    frame_ontvangen = pyqtSignal(str)
    fout = pyqtSignal(str)


class SnifferThread(threading.Thread):
    """Sniffer die in een aparte thread draait zodat de GUI niet blokkeert."""

    def __init__(self, iface, signals: SnifferSignals):
        super().__init__(daemon=True)
        self.iface = iface
        self.signals = signals
        self._stop_event = threading.Event()

    def run(self):
        try:
            # sniff() met timeout stopt na 1s als er geen packets zijn;
            # blijf herstarten totdat stop() is aangeroepen. Het BPF-filter
            # zorgt dat alleen frames met EtherType 0x88B5 worden getoond —
            # zo blijft het logvenster overzichtelijk tussen alle overige
            # verkeer (ARP, IPv4/IPv6, STP, LLDP, ...) op het segment.
            while not self._stop_event.is_set():
                sniff(
                    iface=self.iface,
                    filter=BPF_ETHERTYPE_FILTER,
                    prn=self._verwerk_frame,
                    store=False,
                    stop_filter=lambda pkt: self._stop_event.is_set(),
                    timeout=1,
                )
        except Exception as e:
            self.signals.fout.emit(f"Sniffer-fout: {e}")

    def _verwerk_frame(self, pkt):
        if not pkt.haslayer(Ether):
            return
        eth = pkt[Ether]
        if eth.type != DEFAULT_ETHERTYPE:
            return  # extra vangnet naast het BPF-filter

        tijd = time.strftime("%H:%M:%S")
        lengte = len(pkt)
        payload = bytes(eth.payload)
        try:
            payload_str = payload.decode("utf-8", errors="replace")
        except Exception:
            payload_str = repr(payload)
        payload_hex = payload.hex(" ")

        dst_type = classify_mac(eth.dst)
        src_type = classify_mac(eth.src)

        regel = (
            f"────────────────────────────────────────────\n"
            f"[{tijd}] Ethernet frame ontvangen op {self.iface}\n"
            f"  Destination MAC : {eth.dst}  ({dst_type})\n"
            f"  Source MAC      : {eth.src}  ({src_type})\n"
            f"  EtherType       : 0x{eth.type:04X}\n"
            f"  Framegrootte    : {lengte} bytes\n"
            f"  Payload (tekst) : {payload_str!r}\n"
            f"  Payload (hex)   : {payload_hex}"
        )
        self.signals.frame_ontvangen.emit(regel)

    def stop(self):
        self._stop_event.set()


class HoofdVenster(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Ethernet Messenger — CCNA Lab Tool")
        self.resize(720, 600)

        self.sniffer_thread: SnifferThread | None = None
        self.sniffer_signals = SnifferSignals()
        self.sniffer_signals.frame_ontvangen.connect(self._toon_ontvangen_frame)
        self.sniffer_signals.fout.connect(self._toon_sniffer_fout)

        self._bouw_ui()
        self._controleer_root_rechten()
        self._vul_interfaces()

    # ------------------------------------------------------------------
    # UI opbouw
    # ------------------------------------------------------------------
    def _bouw_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # Waarschuwingslabel (root-rechten)
        self.root_waarschuwing = QLabel("")
        self.root_waarschuwing.setStyleSheet(
            "color: white; background-color: #b03030; padding: 6px; border-radius: 4px;"
        )
        self.root_waarschuwing.setWordWrap(True)
        self.root_waarschuwing.hide()
        layout.addWidget(self.root_waarschuwing)

        # Interface-selectie
        iface_group = QGroupBox("Netwerkinterface")
        iface_layout = QFormLayout()
        self.iface_combo = QComboBox()
        self.iface_combo.currentIndexChanged.connect(self._interface_gewijzigd)
        iface_layout.addRow("Interface:", self.iface_combo)
        iface_group.setLayout(iface_layout)
        layout.addWidget(iface_group)

        # Frame-opbouw
        frame_group = QGroupBox("Ethernet frame opbouwen")
        frame_layout = QFormLayout()

        self.src_mac_edit = QLineEdit()
        frame_layout.addRow("Source MAC:", self.src_mac_edit)

        dst_layout = QHBoxLayout()
        self.dst_mac_edit = QLineEdit()
        self.dst_mac_edit.setPlaceholderText("bijv. 00:11:22:33:44:55")
        broadcast_knop = QPushButton("Broadcast invullen")
        broadcast_knop.clicked.connect(self._vul_broadcast_in)
        dst_layout.addWidget(self.dst_mac_edit)
        dst_layout.addWidget(broadcast_knop)
        frame_layout.addRow("Destination MAC:", dst_layout)

        self.ethertype_label = QLabel(f"0x{DEFAULT_ETHERTYPE:04X} (vast, voor dit lab)")
        frame_layout.addRow("EtherType:", self.ethertype_label)

        self.payload_edit = QLineEdit()
        self.payload_edit.setPlaceholderText("Vrije tekst payload")
        frame_layout.addRow("Payload:", self.payload_edit)

        frame_group.setLayout(frame_layout)
        layout.addWidget(frame_group)

        # Verstuurknop
        verstuur_knop = QPushButton("Frame versturen")
        verstuur_knop.clicked.connect(self._verstuur_frame)
        layout.addWidget(verstuur_knop)

        # Sniffer sectie
        sniffer_group = QGroupBox("Live sniffer")
        sniffer_layout = QVBoxLayout()

        self.sniffer_checkbox = QCheckBox("Sniffer inschakelen")
        self.sniffer_checkbox.stateChanged.connect(self._sniffer_omschakelen)
        sniffer_layout.addWidget(self.sniffer_checkbox)

        self.log_venster = QTextEdit()
        self.log_venster.setReadOnly(True)
        self.log_venster.setStyleSheet("font-family: monospace;")
        sniffer_layout.addWidget(self.log_venster)

        wis_knop = QPushButton("Log wissen")
        wis_knop.clicked.connect(self.log_venster.clear)
        sniffer_layout.addWidget(wis_knop)

        sniffer_group.setLayout(sniffer_layout)
        layout.addWidget(sniffer_group)

    # ------------------------------------------------------------------
    # Root-rechten controle
    # ------------------------------------------------------------------
    def _controleer_root_rechten(self):
        if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() != 0:
            self.root_waarschuwing.setText(
                "⚠ Dit programma draait niet als root. Raw sockets vereisen "
                "verhoogde rechten om Ethernet frames te versturen en te "
                "sniffen.\n\n"
                "Start het programma met:  sudo python3 ethernet_messenger.py\n"
                "Of geef het Python-interpreter de benodigde capabilities:\n"
                "  sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))"
            )
            self.root_waarschuwing.show()

    # ------------------------------------------------------------------
    # Interfaces
    # ------------------------------------------------------------------
    def _vul_interfaces(self):
        self.iface_combo.clear()
        interfaces = get_readable_interfaces()
        if not interfaces:
            self.iface_combo.addItem("Geen interfaces gevonden", "")
            return
        for readable, iface_name in interfaces:
            self.iface_combo.addItem(readable, iface_name)

        # Standaard de eerste fysieke interface selecteren (bijv. de
        # ingebouwde Ethernet- of wifi-adapter), niet zomaar de eerste
        # interface in de lijst (die vaak virtueel is, zoals docker0).
        standaard_index = 0
        for i, (_, iface_name) in enumerate(interfaces):
            if is_physical_interface(iface_name):
                standaard_index = i
                break
        self.iface_combo.setCurrentIndex(standaard_index)
        self._interface_gewijzigd(standaard_index)

    def _interface_gewijzigd(self, index):
        iface_name = self.iface_combo.currentData()
        if not iface_name:
            return
        try:
            mac = get_if_hwaddr(iface_name)
            self.src_mac_edit.setText(mac)
        except Exception:
            self.src_mac_edit.setText("")

    # ------------------------------------------------------------------
    # Frame versturen
    # ------------------------------------------------------------------
    def _vul_broadcast_in(self):
        self.dst_mac_edit.setText(BROADCAST_MAC)

    def _verstuur_frame(self):
        iface_name = self.iface_combo.currentData()
        if not iface_name:
            QMessageBox.warning(self, "Fout", "Geen geldige interface geselecteerd.")
            return

        src_mac = self.src_mac_edit.text().strip()
        dst_mac = self.dst_mac_edit.text().strip()
        payload_tekst = self.payload_edit.text()

        if not dst_mac:
            QMessageBox.warning(
                self, "Fout", "Destination MAC is verplicht."
            )
            return

        try:
            frame = Ether(dst=dst_mac, src=src_mac or None, type=DEFAULT_ETHERTYPE) / payload_tekst.encode("utf-8")
            sendp(frame, iface=iface_name, verbose=False)
            self._log(
                f"[VERZONDEN] src={frame.src} dst={frame.dst} "
                f"ethertype=0x{DEFAULT_ETHERTYPE:04X} payload={payload_tekst!r}"
            )
        except PermissionError:
            QMessageBox.critical(
                self,
                "Onvoldoende rechten",
                "Kan geen raw socket openen. Start dit programma als root "
                "(sudo) of geef Python de juiste capabilities via setcap.\n"
                "Zie README.md voor instructies.",
            )
        except Exception as e:
            QMessageBox.critical(self, "Fout bij versturen", f"Er ging iets mis: {e}")

    # ------------------------------------------------------------------
    # Sniffer
    # ------------------------------------------------------------------
    def _sniffer_omschakelen(self, state):
        if state == Qt.CheckState.Checked.value:
            self._start_sniffer()
        else:
            self._stop_sniffer()

    def _start_sniffer(self):
        iface_name = self.iface_combo.currentData()
        if not iface_name:
            QMessageBox.warning(self, "Fout", "Geen geldige interface geselecteerd.")
            self.sniffer_checkbox.setChecked(False)
            return

        if self.sniffer_thread is not None:
            return

        self.sniffer_thread = SnifferThread(iface_name, self.sniffer_signals)
        try:
            self.sniffer_thread.start()
            self._log(f"[SNIFFER] Gestart op interface {iface_name}.")
        except PermissionError:
            QMessageBox.critical(
                self,
                "Onvoldoende rechten",
                "Kan geen raw socket openen voor sniffen. Start dit "
                "programma als root (sudo) of geef Python de juiste "
                "capabilities via setcap. Zie README.md voor instructies.",
            )
            self.sniffer_checkbox.setChecked(False)
            self.sniffer_thread = None

    def _stop_sniffer(self):
        if self.sniffer_thread is not None:
            self.sniffer_thread.stop()
            self.sniffer_thread = None
            self._log("[SNIFFER] Gestopt.")

    def _toon_ontvangen_frame(self, regel: str):
        self._log(regel)

    def _toon_sniffer_fout(self, foutmelding: str):
        self._log(f"[FOUT] {foutmelding}")
        self.sniffer_checkbox.setChecked(False)

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------
    def _log(self, tekst: str):
        self.log_venster.append(tekst)

    def closeEvent(self, event):
        self._stop_sniffer()
        super().closeEvent(event)


def main():
    app = QApplication(sys.argv)
    venster = HoofdVenster()
    venster.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
