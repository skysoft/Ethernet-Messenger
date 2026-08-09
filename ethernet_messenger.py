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
import re
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zlib

from PyQt6.QtCore import Qt, pyqtSignal, QObject, QRectF, QTimer
from PyQt6.QtGui import QPainter, QColor, QPen, QFont, QActionGroup
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
    QSizePolicy,
    QTabWidget,
    QStackedWidget,
    QListWidget,
    QListWidgetItem,
    QMenu,
)

try:
    from scapy.all import Ether, sendp, sniff, get_if_list, get_if_hwaddr, conf, wrpcap
except ImportError:
    print(
        "Scapy is niet geïnstalleerd. Installeer het met:\n"
        "  sudo pip install --break-system-packages scapy\n"
        "of gebruik een virtuele omgeving (zie README.md)."
    )
    sys.exit(1)


DEFAULT_ETHERTYPE = 0x88B5  # gereserveerd voor experimenteel/onderwijsgebruik
ARP_ETHERTYPE = 0x0806
BPF_ETHERTYPE_FILTER = f"ether proto {DEFAULT_ETHERTYPE:#06x}"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
MIN_DATA_BYTES = 46  # minimale grootte van het Data-veld (Ethernet-norm)

# Modi: elke volgende modus voegt protocol-opties toe aan de te kiezen
# EtherType bij het opbouwen van een frame. Ethernet en ARP zijn
# functioneel uitgewerkt (ARP als leesbare pseudo-ARP-tekst i.p.v. de
# echte binaire ARP-structuur — zie _arp_payload_tekst); IPv4/IPv6
# staan er voorlopig alleen ter illustratie bij, worden in een latere
# fase functioneel uitgewerkt.
MODUS_PROTOCOLLEN = {
    "Mode-A": [("Ethernet (0x88B5)", DEFAULT_ETHERTYPE)],
    "Mode-B": [("Ethernet (0x88B5)", DEFAULT_ETHERTYPE), ("ARP (0x0806)", ARP_ETHERTYPE)],
    "Mode-C": [
        ("Ethernet (0x88B5)", DEFAULT_ETHERTYPE),
        ("ARP (0x0806)", ARP_ETHERTYPE),
        ("IPv4 (0x0800)", 0x0800),
    ],
    "Mode-D": [
        ("Ethernet (0x88B5)", DEFAULT_ETHERTYPE),
        ("ARP (0x0806)", ARP_ETHERTYPE),
        ("IPv4 (0x0800)", 0x0800),
        ("IPv6 (0x86DD)", 0x86DD),
    ],
}
MODUS_OMSCHRIJVING = {
    "Mode-A": "Mode-A — alleen Ethernet",
    "Mode-B": "Mode-B — Ethernet + ARP",
    "Mode-C": "Mode-C — Ethernet + ARP + IPv4",
    "Mode-D": "Mode-D — Ethernet + ARP + IPv4 + IPv6",
}


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


def bouw_payload_bytes(tekst):
    """
    Zet de ingetypte payloadtekst om in bytes, voorafgegaan door een
    2-byte lengteveld. Ethernet vult frames die korter zijn dan de
    minimale framegrootte (60 bytes exclusief FCS) automatisch aan met
    nulbytes (padding). Zonder een expliciet lengteveld zou die padding
    bij ontvangst niet te onderscheiden zijn van de echte payload; met
    het lengteveld kan de ontvanger precies de ingetypte tekst
    terugvinden en de padding herkennen en verbergen.
    """
    inhoud = tekst.encode("utf-8")
    return struct.pack("!H", len(inhoud)) + inhoud


def ontleed_payload(raw: bytes):
    """
    Ontleedt de ruwe payload van een ontvangen frame op basis van het
    2-byte lengteveld dat bouw_payload_bytes() ervoor plaatst.
    Retourneert (werkelijke_payload_bytes, aantal_paddingbytes).
    """
    if len(raw) < 2:
        return raw, 0
    (opgegeven_lengte,) = struct.unpack("!H", raw[:2])
    inhoud = raw[2:]
    if opgegeven_lengte > len(inhoud):
        # Onverwacht frame (niet verzonden door deze applicatie): geen
        # aannames doen over padding, gewoon alles tonen.
        return inhoud, 0
    werkelijke_payload = inhoud[:opgegeven_lengte]
    padding_lengte = len(inhoud) - opgegeven_lengte
    return werkelijke_payload, padding_lengte


# Standaard Ethernet-preamble: 7 bytes afwisselend patroon (0xAA) gevolgd
# door de Start Frame Delimiter (0xAB). Dit is altijd hetzelfde patroon,
# ongeacht de framegrootte.
PREAMBLE_BYTES = bytes([0xAA] * 7 + [0xAB])


def mac_naar_bytes(mac_tekst):
    """
    Zet een (mogelijk nog onvolledig ingetypt) MAC-adres om in 6 bytes,
    zodat de live visualisatie ook tijdens het typen een FCS kan
    voorrekenen. Ontbrekende of ongeldige octetten worden als 0x00
    behandeld.
    """
    delen = re.split(r"[:\-]", mac_tekst.strip()) if mac_tekst else []
    octetten = []
    for i in range(6):
        try:
            octetten.append(int(delen[i], 16) & 0xFF)
        except (IndexError, ValueError):
            octetten.append(0)
    return bytes(octetten)


def bereken_dummy_fcs(dst_mac, src_mac, ethertype, data_bytes):
    """
    Berekent een illustratieve FCS (CRC-32) over de frame-inhoud, zodat
    de weergave verandert zodra de gebruiker iets aan het frame
    aanpast — net zoals een echte FCS afhankelijk is van de
    frame-inhoud. Dit is een educatieve benadering ter illustratie, geen
    exacte reproductie van de FCS zoals die op de kabel wordt verzonden.
    """
    inhoud = mac_naar_bytes(dst_mac) + mac_naar_bytes(src_mac) + struct.pack("!H", ethertype) + data_bytes
    checksum = zlib.crc32(inhoud) & 0xFFFFFFFF
    return checksum.to_bytes(4, "big")


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
    frame_ontvangen = pyqtSignal(object)
    fout = pyqtSignal(str)


class SnifferThread(threading.Thread):
    """Sniffer die in een aparte thread draait zodat de GUI niet blokkeert."""

    def __init__(self, iface, signals: SnifferSignals):
        super().__init__(daemon=True)
        self.iface = iface
        self.signals = signals
        self._stop_event = threading.Event()
        # Lokale raw-socket capture (Scapy/libpcap) vangt op Linux zowel
        # inkomend áls zelf verzonden verkeer op dezelfde interface af —
        # dat gebeurt in de kernel, niet doordat een switch het frame
        # terugstuurt (dat doet een switch nooit naar de poort waar het
        # vandaan kwam). Om de sniffer realistisch te houden ("wat zou
        # een ándere computer op het netwerk zien") worden eigen
        # verzonden frames er hieronder uitgefilterd.
        try:
            self.eigen_mac = get_if_hwaddr(iface)
        except Exception:
            self.eigen_mac = None

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
        if self.eigen_mac and eth.src.lower() == self.eigen_mac.lower():
            return  # eigen uitgaand frame, geen "echt" ontvangen verkeer

        raw_payload = bytes(eth.payload)
        werkelijke_payload, _ = ontleed_payload(raw_payload)
        try:
            payload_str = werkelijke_payload.decode("utf-8", errors="replace")
        except Exception:
            payload_str = repr(werkelijke_payload)

        # raw_payload is de volledige, ongewijzigde inhoud van het
        # Data-veld zoals die over de kabel is gekomen (lengteveld +
        # tekst + eventuele padding) — hiermee kan de ontvanger dezelfde
        # visuele framerepresentatie tonen als de verzender.
        frame_info = {
            "dst_mac": eth.dst,
            "src_mac": eth.src,
            "ethertype_hex": f"0x{eth.type:04X}",
            "ethertype_int": eth.type,
            "payload_tekst": payload_str,
            "data_bytes": raw_payload,
        }
        self.signals.frame_ontvangen.emit(frame_info)

    def stop(self):
        self._stop_event.set()


class FrameVisualisatieWidget(QWidget):
    """
    Zuiver visuele weergave van de opbouw van het Ethernet frame dat
    (live, tijdens het intypen) verstuurd zou worden.

    Preamble en FCS worden getekend ter illustratie van de volledige
    frameopbouw, maar zijn grijs gemarkeerd: deze applicatie (en Scapy)
    bouwt en verstuurt in werkelijkheid alleen Destination MAC t/m Data —
    Preamble en FCS worden door de netwerkkaart/driver toegevoegd
    respectievelijk gecontroleerd en zijn hier niet daadwerkelijk
    aanwezig of zichtbaar.
    """

    VELDEN_BUITEN_APP = {"Preamble", "FCS"}

    def __init__(self, parent=None):
        super().__init__(parent)
        # setFixedHeight (i.p.v. setMinimumHeight) omdat deze widget geen
        # eigen sizeHint() heeft: zonder een concrete hoogte-hint heeft
        # een "Fixed" verticale size policy niets om op te ankeren, en
        # rekt de widget alsnog uit zodra er extra ruimte beschikbaar is
        # (bijv. bij het gemaximaliseerd opstarten van de applicatie).
        self.setFixedHeight(150)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._velden = []
        self._leeg_bericht = ""

    def toon_leeg(self, bericht):
        """
        Toont geen frame-inhoud: geen enkel veld wordt ingevuld, ook niet
        Preamble/Type/FCS. Bedoeld voor de ontvangstkant zolang er nog
        geen frame is binnengekomen — anders zou de weergave onterecht
        suggereren dat er al iets ontvangen is.
        """
        self._velden = []
        self._leeg_bericht = bericht
        self.update()

    def toon_frame(self, dst_mac, src_mac, ethertype_hex, ethertype_int, payload_tekst, data_bytes):
        """
        dst_mac/src_mac: ingevoerde MAC-adressen (tekst).
        ethertype_hex/ethertype_int: EtherType als hex-tekst resp. int.
        payload_tekst: de door de gebruiker ingetypte payloadtekst.
        data_bytes: de volledige, al aangevulde inhoud van het Data-veld
            zoals die daadwerkelijk verstuurd zou worden (lengteveld +
            tekst + eventuele padding).
        """
        fcs_bytes = bereken_dummy_fcs(dst_mac, src_mac, ethertype_int, data_bytes)

        self._velden = [
            ("Preamble", len(PREAMBLE_BYTES), PREAMBLE_BYTES.hex(" ").upper()),
            ("Destination address", 6, (dst_mac or "-").upper()),
            ("Source address", 6, (src_mac or "-").upper()),
            ("Type", 2, ethertype_hex),
            ("Data", len(data_bytes), payload_tekst if payload_tekst else "(leeg)"),
            ("FCS", len(fcs_bytes), fcs_bytes.hex(" ").upper()),
        ]
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        if not self._velden:
            if self._leeg_bericht:
                font_leeg = QFont(self.font().family())
                font_leeg.setPointSize(9)
                font_leeg.setItalic(True)
                painter.setFont(font_leeg)
                painter.setPen(QColor("#888888"))
                painter.drawText(
                    self.rect(),
                    int(Qt.AlignmentFlag.AlignCenter) | int(Qt.TextFlag.TextWordWrap),
                    self._leeg_bericht,
                )
            painter.end()
            return

        marge = 8
        top = 22
        onder_ruimte = 48
        hoogte_box = max(30, self.height() - top - onder_ruimte)
        beschikbare_breedte = self.width() - 2 * marge

        # Byte-gewicht per veld voor de breedte van de tekening: kleine
        # velden krijgen een minimumbreedte zodat de tekst leesbaar
        # blijft, grote velden (Data) worden begrensd zodat ze de rest
        # niet volledig wegdrukken.
        gewichten = [max(6, min(lengte, 30)) for _, lengte, _ in self._velden]
        totaal_gewicht = sum(gewichten)

        basis_font = QFont(self.font().family())

        x = float(marge)
        for (naam, lengte, waarde), gewicht in zip(self._velden, gewichten):
            breedte = beschikbare_breedte * gewicht / totaal_gewicht
            rect = QRectF(x, top, breedte, hoogte_box)
            is_buiten_app = naam in self.VELDEN_BUITEN_APP
            vulkleur = QColor("#d8d8d8") if is_buiten_app else QColor("#8ec7f0")
            randkleur = QColor("#777777") if is_buiten_app else QColor("#12467a")

            # bytelengte-label boven de box
            font_label = QFont(basis_font)
            font_label.setPointSize(8)
            painter.setFont(font_label)
            painter.setPen(QColor("#555555"))
            painter.drawText(
                QRectF(x, 2, breedte, top - 4),
                Qt.AlignmentFlag.AlignCenter,
                f"{lengte} B",
            )

            # veldbox
            pen = QPen(randkleur)
            pen.setWidthF(1.4)
            painter.setPen(pen)
            painter.setBrush(vulkleur)
            painter.drawRect(rect)

            # werkelijke waarde, in het vet, IN de box
            painter.save()
            painter.setClipRect(rect)
            font_waarde = QFont(basis_font)
            font_waarde.setPointSize(8)
            font_waarde.setBold(True)
            painter.setFont(font_waarde)
            painter.setPen(QColor("#444444") if is_buiten_app else QColor("#0b2e52"))
            painter.drawText(
                rect,
                int(Qt.AlignmentFlag.AlignCenter) | int(Qt.TextFlag.TextWordWrap),
                str(waarde),
            )
            painter.restore()

            # veldnaam, klein, ONDER de box — geclipt op het eigen
            # widget-oppervlak zodat een (te) lang woord nooit doorloopt
            # in wat daaronder in de lay-out staat.
            painter.save()
            painter.setClipRect(QRectF(x, 0, breedte, self.height()))
            font_naam = QFont(basis_font)
            font_naam.setPointSize(7)
            font_naam.setItalic(True)
            painter.setFont(font_naam)
            painter.setPen(QColor("#333333"))
            naam_rect = QRectF(x, top + hoogte_box + 2, breedte, onder_ruimte - 2)
            painter.drawText(
                naam_rect,
                int(Qt.AlignmentFlag.AlignHCenter) | int(Qt.AlignmentFlag.AlignTop) | int(Qt.TextFlag.TextWordWrap),
                naam,
            )
            painter.restore()

            x += breedte

        # dashed buitenrand om het hele frame, ter illustratie dat dit de
        # conceptuele volledige framegrootte op de kabel is
        painter.setPen(QPen(QColor("#12467a"), 1.4, Qt.PenStyle.DashLine))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawRect(QRectF(marge, top, beschikbare_breedte, hoogte_box))

        painter.end()


class HoofdVenster(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Ethernet Messenger — CCNA Lab Tool")
        self.resize(760, 720)

        self.sniffer_thread: SnifferThread | None = None
        self.sniffer_signals = SnifferSignals()
        self.sniffer_signals.frame_ontvangen.connect(self._toon_ontvangen_frame)
        self.sniffer_signals.fout.connect(self._toon_sniffer_fout)

        self._actief_ethertype = DEFAULT_ETHERTYPE
        self._actieve_interface = ""

        self._bouw_ui()
        self._controleer_root_rechten()
        self._vul_interfaces()

    # ------------------------------------------------------------------
    # UI opbouw
    # ------------------------------------------------------------------
    def _bouw_ui(self):
        self._bouw_menu()

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

        tabs = QTabWidget()
        layout.addWidget(tabs)
        tabs.addTab(self._bouw_verzenden_tab(), "Verzenden")
        tabs.addTab(self._bouw_ontvangen_tab(), "Ontvangen")

        self._bouw_statusbalk()

        # De modus-acties bestaan al (uit _bouw_menu), maar het effect
        # ervan (ethertype_stack/protocol_combo) kon pas na het bouwen
        # van de tabs toegepast worden — daarom hier expliciet de
        # standaardmodus (Mode-A) toepassen.
        self._toepassen_modus("Mode-A")

    def _bouw_menu(self):
        """
        Menubalk met "Instellingen" → submenu's "Interface" en "Modus".
        Deze gelden voor de hele applicatie (beide tabbladen), vandaar
        de plek in de menubalk in plaats van in een tabblad.
        """
        instellingen_menu = self.menuBar().addMenu("&Instellingen")

        # Interface-submenu wordt pas gevuld in _vul_interfaces(), zodra
        # de daadwerkelijk beschikbare interfaces bekend zijn.
        self.interface_menu = instellingen_menu.addMenu("Interface")
        self.interface_actiegroep = QActionGroup(self)
        self.interface_actiegroep.setExclusive(True)

        self.modus_menu = instellingen_menu.addMenu("Modus")
        self.modus_actiegroep = QActionGroup(self)
        self.modus_actiegroep.setExclusive(True)
        for sleutel in ("Mode-A", "Mode-B", "Mode-C", "Mode-D"):
            actie = self.modus_menu.addAction(MODUS_OMSCHRIJVING[sleutel])
            actie.setCheckable(True)
            actie.setData(sleutel)
            actie.setActionGroup(self.modus_actiegroep)
            actie.triggered.connect(self._modus_actie_gekozen)
            if sleutel == "Mode-A":
                actie.setChecked(True)

    def _bouw_statusbalk(self):
        """
        Toont de actieve interface en modus onderin het venster, zodat
        die altijd zichtbaar blijven ook al zit de keuze nu in een menu.
        """
        statusbalk = self.statusBar()
        self._interface_status_label = QLabel("Interface: —")
        self._modus_status_label = QLabel(f"Modus: {MODUS_OMSCHRIJVING['Mode-A']}")
        statusbalk.addPermanentWidget(self._interface_status_label)
        statusbalk.addPermanentWidget(QLabel("  |  "))
        statusbalk.addPermanentWidget(self._modus_status_label)

    def _bouw_verzenden_tab(self):
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)

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

        # In Mode-A een vast label; vanaf Mode-B een protocol-keuzelijst
        # (zie _toepassen_modus). Een QStackedWidget zodat Mode-A er
        # precies zo uitziet als voorheen.
        self.ethertype_stack = QStackedWidget()
        # Verticaal vast, anders trekt deze rij (als enige "Preferred"
        # veld in dit formulier, i.p.v. "Fixed" zoals de QLineEdits) alle
        # overtollige ruimte naar zich toe zodra het venster groter is
        # dan zijn natuurlijke grootte — bijv. bij het gemaximaliseerd
        # opstarten van de applicatie.
        self.ethertype_stack.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        self.ethertype_label = QLabel(f"0x{DEFAULT_ETHERTYPE:04X} (vast, voor dit lab)")
        self.ethertype_stack.addWidget(self.ethertype_label)
        self.protocol_combo = QComboBox()
        self.protocol_combo.currentIndexChanged.connect(self._protocol_gewijzigd)
        self.ethertype_stack.addWidget(self.protocol_combo)
        frame_layout.addRow("EtherType:", self.ethertype_stack)

        # ARP-subopties: alleen zichtbaar als het actieve EtherType ARP
        # is (dus vanaf Mode-B, waar ARP als keuze verschijnt). "Soort
        # ARP" en "IP-adres" bepalen samen de leesbare pseudo-ARP-tekst
        # die als payload gebruikt wordt — zie _arp_payload_tekst().
        self.arp_opties_widget = QWidget()
        arp_opties_layout = QFormLayout(self.arp_opties_widget)
        arp_opties_layout.setContentsMargins(0, 0, 0, 0)
        self.arp_soort_combo = QComboBox()
        self.arp_soort_combo.addItem("Verzend ARP aanvraag", "aanvraag")
        self.arp_soort_combo.addItem("Verzend ARP antwoord", "antwoord")
        self.arp_soort_combo.currentIndexChanged.connect(self._arp_gewijzigd)
        arp_opties_layout.addRow("Soort ARP:", self.arp_soort_combo)
        self.arp_ip_edit = QLineEdit()
        self.arp_ip_edit.setPlaceholderText("bijv. 192.168.1.1")
        self.arp_ip_edit.textChanged.connect(self._arp_gewijzigd)
        arp_opties_layout.addRow("IP-adres:", self.arp_ip_edit)
        self.arp_opties_widget.setVisible(False)
        frame_layout.addRow(self.arp_opties_widget)

        modus_uitleg = QLabel(
            "Mode-A biedt alleen Ethernet-framing (de huidige "
            "functionaliteit). Vanaf Mode-B (Instellingen → Modus) "
            "verschijnen er extra protocol-opties bij het opbouwen van "
            "een frame, ter voorbereiding op latere uitbreidingen. "
            "Ethernet en ARP kunnen daadwerkelijk verzonden worden "
            "(de ARP-payload is een leesbare pseudo-ARP-tekst, geen "
            "echte binaire ARP-structuur); IPv4/IPv6 zijn nog niet "
            "functioneel. Ontvangen frames worden, ongeacht de gekozen "
            "modus, nog altijd gefilterd op Ethernet (EtherType "
            "0x88B5) — ARP-frames zijn dus wel te verzenden en in "
            "Wireshark te bekijken, maar nog niet in de sniffer van "
            "deze applicatie."
        )
        modus_uitleg.setWordWrap(True)
        modus_uitleg.setStyleSheet("color: #666666; font-size: 11px;")
        modus_uitleg.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        frame_layout.addRow(modus_uitleg)

        self.payload_edit = QLineEdit()
        self.payload_edit.setPlaceholderText("Vrije tekst payload")
        frame_layout.addRow("Payload:", self.payload_edit)

        frame_group.setLayout(frame_layout)
        tab_layout.addWidget(frame_group)

        # Live visuele weergave van het op te bouwen frame
        visualisatie_group = QGroupBox("Visuele weergave van het frame (live)")
        visualisatie_layout = QVBoxLayout()
        self.frame_visualisatie = FrameVisualisatieWidget()
        visualisatie_layout.addWidget(self.frame_visualisatie)
        visualisatie_layout.addSpacing(8)
        visualisatie_uitleg = QLabel(
            "Preamble en FCS (grijs) tonen illustratieve waarden — in "
            "werkelijkheid worden die door de netwerkkaart toegevoegd "
            "(Preamble) resp. berekend en gecontroleerd (FCS). Deze "
            "applicatie bouwt en verstuurt zelf alleen Destination MAC "
            "t/m Data."
        )
        visualisatie_uitleg.setWordWrap(True)
        visualisatie_uitleg.setStyleSheet("color: #666666; font-size: 11px;")
        visualisatie_layout.addWidget(visualisatie_uitleg)
        visualisatie_group.setLayout(visualisatie_layout)
        tab_layout.addWidget(visualisatie_group)

        self.dst_mac_edit.textChanged.connect(self._bijwerken_visualisatie)
        self.src_mac_edit.textChanged.connect(self._bijwerken_visualisatie)
        self.payload_edit.textChanged.connect(self._bijwerken_visualisatie)
        self._bijwerken_visualisatie()

        # Verstuurknop
        verstuur_knop = QPushButton("Frame versturen")
        verstuur_knop.clicked.connect(self._verstuur_frame)
        tab_layout.addWidget(verstuur_knop)

        # Vangt overtollige verticale ruimte op als blanco ruimte
        # onderaan (bijv. bij het gemaximaliseerd opstarten van de
        # applicatie), zodat geen enkele rij daarboven uitgerekt wordt.
        tab_layout.addStretch(1)

        return tab

    def _bouw_ontvangen_tab(self):
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)

        sniffer_group = QGroupBox("Live sniffer")
        sniffer_layout = QVBoxLayout()

        self.sniffer_checkbox = QCheckBox("Sniffer inschakelen")
        self.sniffer_checkbox.stateChanged.connect(self._sniffer_omschakelen)
        sniffer_layout.addWidget(self.sniffer_checkbox)

        # Geselecteerd frame — zelfde visuele weergave als aan de
        # verzendkant, zodat verzendende en ontvangende student precies
        # hetzelfde frame te zien krijgen. Zolang er nog niets is
        # binnengekomen, wordt er geen frame-inhoud getoond (geen nep
        # Preamble/Type/FCS).
        self.ontvangst_visualisatie = FrameVisualisatieWidget()
        self.ontvangst_visualisatie.toon_leeg(
            "Nog geen frame ontvangen — schakel de sniffer in en wacht op "
            "inkomend verkeer met EtherType 0x88B5."
        )
        sniffer_layout.addWidget(self.ontvangst_visualisatie)
        sniffer_layout.addSpacing(8)
        ontvangst_uitleg = QLabel(
            "Toont het geselecteerde frame uit de lijst hieronder, op "
            "dezelfde manier weergegeven als bij de verzendende student — "
            "inclusief een FCS die opnieuw berekend is uit de ontvangen "
            "inhoud."
        )
        ontvangst_uitleg.setWordWrap(True)
        ontvangst_uitleg.setStyleSheet("color: #666666; font-size: 11px;")
        sniffer_layout.addWidget(ontvangst_uitleg)

        # Geschiedenis: elk ontvangen frame komt in deze lijst; door een
        # eerder frame aan te klikken wordt de visualisatie erboven
        # bijgewerkt, zodat je kunt terugkijken naar eerder ontvangen
        # frames.
        sniffer_layout.addWidget(QLabel("Ontvangen frames (klik om terug te kijken):"))
        self.frame_lijst = QListWidget()
        self.frame_lijst.setMaximumHeight(140)
        self.frame_lijst.currentRowChanged.connect(self._frame_geschiedenis_geselecteerd)
        sniffer_layout.addWidget(self.frame_lijst)

        lijst_knoppen = QHBoxLayout()
        lijst_wis_knop = QPushButton("Lijst wissen")
        lijst_wis_knop.clicked.connect(self._wis_frame_geschiedenis)
        lijst_knoppen.addWidget(lijst_wis_knop)
        wireshark_knop = QPushButton("Open geselecteerd frame in Wireshark")
        wireshark_knop.clicked.connect(self._open_in_wireshark)
        lijst_knoppen.addWidget(wireshark_knop)
        sniffer_layout.addLayout(lijst_knoppen)

        self.log_venster = QTextEdit()
        self.log_venster.setReadOnly(True)
        self.log_venster.setStyleSheet("font-family: monospace;")
        self.log_venster.setMaximumHeight(90)
        sniffer_layout.addWidget(self.log_venster)

        wis_knop = QPushButton("Log wissen")
        wis_knop.clicked.connect(self.log_venster.clear)
        sniffer_layout.addWidget(wis_knop)
        sniffer_layout.addStretch(1)

        sniffer_group.setLayout(sniffer_layout)
        tab_layout.addWidget(sniffer_group)
        tab_layout.addStretch(1)

        return tab

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
        self.interface_menu.clear()
        for actie in list(self.interface_actiegroep.actions()):
            self.interface_actiegroep.removeAction(actie)

        interfaces = get_readable_interfaces()
        if not interfaces:
            actie = self.interface_menu.addAction("Geen interfaces gevonden")
            actie.setEnabled(False)
            self._interface_actie_toepassen("")
            return

        # Standaard de eerste fysieke interface selecteren (bijv. de
        # ingebouwde Ethernet- of wifi-adapter), niet zomaar de eerste
        # interface in de lijst (die vaak virtueel is, zoals docker0).
        standaard_index = 0
        for i, (_, iface_name) in enumerate(interfaces):
            if is_physical_interface(iface_name):
                standaard_index = i
                break

        for i, (readable, iface_name) in enumerate(interfaces):
            actie = self.interface_menu.addAction(readable)
            actie.setCheckable(True)
            actie.setData(iface_name)
            actie.setActionGroup(self.interface_actiegroep)
            actie.triggered.connect(self._interface_actie_gekozen)
            if i == standaard_index:
                actie.setChecked(True)

        self._interface_actie_toepassen(interfaces[standaard_index][1])

    def _interface_actie_gekozen(self):
        actie = self.sender()
        if actie is None:
            return
        self._interface_actie_toepassen(actie.data())

    def _interface_actie_toepassen(self, iface_name):
        self._actieve_interface = iface_name
        if iface_name:
            try:
                mac = get_if_hwaddr(iface_name)
                self.src_mac_edit.setText(mac)
            except Exception:
                self.src_mac_edit.setText("")
        else:
            self.src_mac_edit.setText("")
        self._interface_status_label.setText(f"Interface: {iface_name or '—'}")

    # ------------------------------------------------------------------
    # Frame versturen
    # ------------------------------------------------------------------
    def _vul_broadcast_in(self):
        self.dst_mac_edit.setText(BROADCAST_MAC)

    def _modus_actie_gekozen(self):
        actie = self.sender()
        if actie is None:
            return
        self._toepassen_modus(actie.data())

    def _toepassen_modus(self, modus_sleutel):
        if modus_sleutel == "Mode-A":
            self.ethertype_stack.setCurrentWidget(self.ethertype_label)
            self._actief_ethertype = DEFAULT_ETHERTYPE
        else:
            protocollen = MODUS_PROTOCOLLEN[modus_sleutel]
            self.protocol_combo.blockSignals(True)
            self.protocol_combo.clear()
            for naam, waarde in protocollen:
                self.protocol_combo.addItem(naam, waarde)
            self.protocol_combo.setCurrentIndex(0)
            self.protocol_combo.blockSignals(False)
            self._actief_ethertype = protocollen[0][1]
            self.ethertype_stack.setCurrentWidget(self.protocol_combo)
        self._modus_status_label.setText(f"Modus: {MODUS_OMSCHRIJVING[modus_sleutel]}")
        self._bijwerken_arp_status()

    def _protocol_gewijzigd(self, index):
        if index < 0:
            return
        waarde = self.protocol_combo.itemData(index)
        if waarde is None:
            return
        self._actief_ethertype = waarde
        self._bijwerken_arp_status()

    # ------------------------------------------------------------------
    # ARP-subopties (alleen relevant als EtherType ARP gekozen is)
    # ------------------------------------------------------------------
    def _arp_gewijzigd(self, *_args):
        self._bijwerken_arp_status()

    def _arp_payload_tekst(self):
        ip = self.arp_ip_edit.text().strip() or "?"
        soort = self.arp_soort_combo.currentData()
        if soort == "antwoord":
            return f"IP-adres {ip} hoort bij mij."
        return f"Wie heeft IP adres {ip}, vertel het mij."

    def _bijwerken_arp_status(self):
        """
        Toont/verbergt de ARP-subopties en dwingt, als ARP actief is, de
        bijbehorende Destination MAC en payload af in de gewone velden
        (die daarvoor tijdelijk uitgeschakeld worden) — zodat de rest
        van de applicatie (visualisatie, versturen) ongewijzigd gewoon
        dst_mac_edit/payload_edit kan blijven uitlezen.
        """
        is_arp = self._actief_ethertype == ARP_ETHERTYPE
        self.arp_opties_widget.setVisible(is_arp)

        if not is_arp:
            self.dst_mac_edit.setEnabled(True)
            self.payload_edit.setEnabled(True)
            self._bijwerken_visualisatie()
            return

        soort = self.arp_soort_combo.currentData()
        if soort == "aanvraag":
            self.dst_mac_edit.setEnabled(False)
            self.dst_mac_edit.setText(BROADCAST_MAC)
        else:
            # Een ARP-antwoord is unicast: de student vult zelf de MAC
            # van de oorspronkelijke aanvrager in.
            self.dst_mac_edit.setEnabled(True)

        self.payload_edit.setEnabled(False)
        self.payload_edit.setText(self._arp_payload_tekst())
        self._bijwerken_visualisatie()

    def _bijwerken_visualisatie(self):
        dst_mac = self.dst_mac_edit.text().strip()
        src_mac = self.src_mac_edit.text().strip()
        payload_tekst = self.payload_edit.text()

        data_bytes = bouw_payload_bytes(payload_tekst)
        if len(data_bytes) < MIN_DATA_BYTES:
            data_bytes += b"\x00" * (MIN_DATA_BYTES - len(data_bytes))

        self.frame_visualisatie.toon_frame(
            dst_mac=dst_mac,
            src_mac=src_mac,
            ethertype_hex=f"0x{self._actief_ethertype:04X}",
            ethertype_int=self._actief_ethertype,
            payload_tekst=payload_tekst,
            data_bytes=data_bytes,
        )

    def _verstuur_frame(self):
        iface_name = self._actieve_interface
        if not iface_name:
            QMessageBox.warning(self, "Fout", "Geen geldige interface geselecteerd.")
            return

        if self._actief_ethertype not in (DEFAULT_ETHERTYPE, ARP_ETHERTYPE):
            QMessageBox.information(
                self,
                "Nog niet beschikbaar",
                "Dit protocol is in deze versie nog niet functioneel "
                "geïmplementeerd — er kan op dit moment alleen "
                "daadwerkelijk Ethernet (0x88B5) en ARP (0x0806) "
                "verzonden worden. Kies een van die twee in de "
                "protocollijst, of zet de modus terug naar Mode-A.",
            )
            return

        if self._actief_ethertype == ARP_ETHERTYPE and not self.arp_ip_edit.text().strip():
            QMessageBox.warning(self, "Fout", "Vul een IP-adres in voor het ARP-bericht.")
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
            frame = Ether(dst=dst_mac, src=src_mac or None, type=self._actief_ethertype) / bouw_payload_bytes(payload_tekst)
            sendp(frame, iface=iface_name, verbose=False)
            self._log(
                f"[VERZONDEN] src={frame.src} dst={frame.dst} "
                f"ethertype=0x{self._actief_ethertype:04X} payload={payload_tekst!r}"
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
        iface_name = self._actieve_interface
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

    def _toon_ontvangen_frame(self, frame_info: dict):
        tijd = time.strftime("%H:%M:%S")
        item_tekst = (
            f"[{tijd}] {frame_info['dst_mac']} ← {frame_info['src_mac']}  "
            f"{frame_info['payload_tekst']!r}"
        )
        item = QListWidgetItem(item_tekst)
        item.setData(Qt.ItemDataRole.UserRole, frame_info)
        self.frame_lijst.addItem(item)
        # Springt automatisch mee naar het nieuwste frame; via de lijst
        # kan de gebruiker daarna terugklikken naar een eerder frame.
        self.frame_lijst.setCurrentItem(item)
        self.frame_lijst.scrollToItem(item)

        self._log(f"[{tijd}] Frame ontvangen — zie visuele weergave hierboven.")

    def _frame_geschiedenis_geselecteerd(self, rij):
        if rij < 0:
            return
        item = self.frame_lijst.item(rij)
        if item is None:
            return
        frame_info = item.data(Qt.ItemDataRole.UserRole)
        self.ontvangst_visualisatie.toon_frame(
            dst_mac=frame_info["dst_mac"],
            src_mac=frame_info["src_mac"],
            ethertype_hex=frame_info["ethertype_hex"],
            ethertype_int=frame_info["ethertype_int"],
            payload_tekst=frame_info["payload_tekst"],
            data_bytes=frame_info["data_bytes"],
        )

    def _wis_frame_geschiedenis(self):
        self.frame_lijst.clear()
        self.ontvangst_visualisatie.toon_leeg(
            "Nog geen frame ontvangen — schakel de sniffer in en wacht op "
            "inkomend verkeer met EtherType 0x88B5."
        )

    def _open_in_wireshark(self):
        item = self.frame_lijst.currentItem()
        if item is None:
            QMessageBox.information(
                self,
                "Geen frame geselecteerd",
                "Selecteer eerst een frame in de lijst hierboven.",
            )
            return

        frame_info = item.data(Qt.ItemDataRole.UserRole)
        frame = Ether(
            dst=frame_info["dst_mac"],
            src=frame_info["src_mac"],
            type=frame_info["ethertype_int"],
        ) / frame_info["data_bytes"]

        try:
            with tempfile.NamedTemporaryFile(
                prefix="ethernet_messenger_", suffix=".pcap", delete=False
            ) as tmp:
                pcap_pad = tmp.name
            wrpcap(pcap_pad, [frame])
        except Exception as e:
            QMessageBox.critical(self, "Fout", f"Kon geen pcap-bestand aanmaken: {e}")
            return

        try:
            subprocess.Popen(["wireshark", "-r", pcap_pad])
        except FileNotFoundError:
            QMessageBox.critical(
                self,
                "Wireshark niet gevonden",
                "Wireshark kon niet gestart worden. Installeer het met:\n"
                "  sudo apt install wireshark\n\n"
                f"Het frame is wel opgeslagen als:\n{pcap_pad}",
            )
        except Exception as e:
            QMessageBox.critical(self, "Fout bij starten van Wireshark", f"Er ging iets mis: {e}")

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
    # showMaximized() direct aanroepen wordt door sommige window managers
    # genegeerd als het venster nog niet bij de WM geregistreerd is (dus
    # vóórdat de event-loop draait). Via een timer van 0ms gebeurt de
    # maximalisatie pas zodra de event-loop actief is, wat betrouwbaarder
    # werkt.
    QTimer.singleShot(0, venster.showMaximized)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
