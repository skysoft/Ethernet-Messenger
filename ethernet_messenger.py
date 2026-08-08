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
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def get_readable_interfaces():
    """
    Geeft een lijst van (leesbare_naam, scapy_interface_naam) terug voor
    alle beschikbare netwerkinterfaces.
    """
    interfaces = []
    try:
        for iface_name in get_if_list():
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
            sniff(
                iface=self.iface,
                prn=self._verwerk_frame,
                store=False,
                stop_filter=lambda pkt: self._stop_event.is_set(),
                timeout=1,
            )
            # sniff() met timeout stopt na 1s als er geen packets zijn;
            # blijf herstarten totdat stop() is aangeroepen.
            while not self._stop_event.is_set():
                sniff(
                    iface=self.iface,
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
        tijd = time.strftime("%H:%M:%S")
        lengte = len(pkt)
        payload = bytes(eth.payload)
        try:
            payload_str = payload.decode("utf-8", errors="replace")
        except Exception:
            payload_str = repr(payload)

        regel = (
            f"[{tijd}] src={eth.src} dst={eth.dst} "
            f"ethertype=0x{eth.type:04X} lengte={lengte}B "
            f"payload={payload_str!r}"
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

        self.ethertype_edit = QLineEdit(f"0x{DEFAULT_ETHERTYPE:04X}")
        frame_layout.addRow("EtherType:", self.ethertype_edit)

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
        self._interface_gewijzigd(0)

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
        ethertype_tekst = self.ethertype_edit.text().strip()
        payload_tekst = self.payload_edit.text()

        if not dst_mac:
            QMessageBox.warning(
                self, "Fout", "Destination MAC is verplicht."
            )
            return

        try:
            ethertype = int(ethertype_tekst, 16) if ethertype_tekst.lower().startswith("0x") else int(ethertype_tekst)
        except ValueError:
            QMessageBox.warning(
                self, "Fout", "EtherType is ongeldig. Gebruik bijv. 0x88B5."
            )
            return

        try:
            frame = Ether(dst=dst_mac, src=src_mac or None, type=ethertype) / payload_tekst.encode("utf-8")
            sendp(frame, iface=iface_name, verbose=False)
            self._log(
                f"[VERZONDEN] src={frame.src} dst={frame.dst} "
                f"ethertype=0x{ethertype:04X} payload={payload_tekst!r}"
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
