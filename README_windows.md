# Ethernet Messenger — Windows-versie

Dit is de **Windows-variant** van Ethernet Messenger (`ethernet_messenger_windows.py`), gebouwd als **aanvulling** op de Linux/Debian-versie (`ethernet_messenger.py`) — niet als vervanging. Bedoeld voor gebruik op de eigen laptops van studenten (bijv. thuis oefenen, of in een lab waar niet iedereen een Linux-VM heeft), naast de Debian/KDE-versie die in de les gebruikt wordt.

> ⚠️ **Zelfde waarschuwing als de Linux-versie:** deze tool is uitsluitend
> bedoeld voor gecontroleerde lab-/testomgevingen (bijv. een geïsoleerd
> VLAN, een hotspot tussen twee studentlaptops, of een Cisco Modeling Labs
> (CML)-topologie). Gebruik deze tool **nooit** op productienetwerken of
> een netwerk waar je geen toestemming voor hebt. Het versturen van ruwe
> Ethernet frames met een handmatig bepaald source MAC-adres
> (MAC-spoofing) kan netwerken verstoren.

## Functionaliteit

Identiek aan de Linux-versie — zie de uitgebreide feature-beschrijving in
[`README.md`](README.md#functionaliteit) (tabbladen Verzenden/Ontvangen,
Mode-A t/m Mode-D, ARP/IPv4/IPv6 opbouwen en ontvangen, live
framevisualisatie, sniffer met geschiedenislijst, Wireshark-integratie,
enz.). Dit document beschrijft alleen wat **anders** is op Windows.

## Wat is er anders dan de Linux-versie?

Raw sockets werken op Windows fundamenteel anders dan op Linux (geen
kernel-eigen `AF_PACKET`-sockets), dus de volgende onderdelen zijn
Windows-specifiek geïmplementeerd:

- **Npcap in plaats van de Linux-kernel** voor het bouwen/versturen/
  sniffen van raw Ethernet frames (zie Vereisten hieronder).
- **Administrator-rechten in plaats van root/sudo/setcap.** Het
  programma toont een duidelijke waarschuwing (met instructie) als het
  niet als Administrator draait.
- **Interface-detectie** (welke interface is de loopback-adapter, welke
  is "waarschijnlijk fysiek" voor de standaardkeuze) gebruikt op Windows
  trefwoorden in de adapterbeschrijving (bijv. "Virtual", "VPN",
  "VMware", "Hyper-V", "WAN Miniport" worden als niet-fysiek beschouwd)
  in plaats van Linux' `/sys/class/net/.../device`, dat op Windows niet
  bestaat. Dit is een heuristiek, geen garantie — controleer bij twijfel
  zelf via **Instellingen → Interface** welke adapter geselecteerd is.
- **Interfacenamen**: Scapy geeft op Windows intern een technische naam
  door (`\Device\NPF_{GUID}`); de applicatie toont in het interfacemenu
  de herkenbare Windows-verbindingsnaam (bijv. "Ethernet" of "Wi-Fi")
  plus de stuurprogramma-omschrijving.
- **Wireshark-integratie** zoekt `wireshark.exe` op de gebruikelijke
  installatielocatie (`Program Files\Wireshark`) in plaats van aan te
  nemen dat het op PATH staat.

Alle overige code (framevisualisatie, ARP/IPv4/IPv6-opbouw, sniffer-
logica, protocolvalidatie) is exact hetzelfde als de Linux-versie.

## Vereisten

- Windows 10 of 11
- Python 3 (van [python.org](https://www.python.org/downloads/) — vink
  bij installatie "Add python.exe to PATH" aan)
- [**Npcap**](https://npcap.com/#download) — installeer met de
  standaardopties (WinPcap-compatibiliteitsmodus aangevinkt blijft
  meestal al standaard aan)
- PyQt6 en Scapy (zie Installatie hieronder)
- Administrator-rechten om het programma te draaien
- Wireshark (optioneel, voor "Open geselecteerd frame in Wireshark"):
  [wireshark.org/download.html](https://www.wireshark.org/download.html)

## Installatie

### Optie A: automatisch installatiescript (aanbevolen)

Dit project bevat [`installeer_windows.ps1`](installeer_windows.ps1), dat
Python 3, Npcap, PyQt6 en Scapy voor je installeert (en optioneel
Wireshark). Open PowerShell in de map met dit project en voer uit:

```bash
powershell -ExecutionPolicy Bypass -File .\installeer_windows.ps1
```

Het script vraagt zelf om Administrator-rechten (nodig voor Npcap). Let op:
de **gratis** Npcap-installer ondersteunt geen volledig automatische
(silent) installatie — het script downloadt de officiele installer en opent
die voor je; doorloop de wizard met de standaardopties (een paar keer
"Next"/"I Agree"/"Install"). De rest (Python, PyQt6, Scapy, optioneel
Wireshark) verloopt volledig automatisch via `winget`/`pip`.

### Optie B: handmatig

Zorg eerst zelf voor Python 3 (zie Vereisten) en Npcap
([npcap.com/#download](https://npcap.com/#download), standaardopties).
Open daarna een Opdrachtprompt of PowerShell in de map met dit project:

```bash
pip install PyQt6 scapy
```

Gebruik je liever een virtuele omgeving:

```bash
python -m venv venv
venv\Scripts\activate
pip install PyQt6 scapy
```

## Starten

Raw sockets vereisen verhoogde rechten, net als op Linux. Start het
programma **als Administrator**:

1. Open een Opdrachtprompt of PowerShell via rechtermuisknop → **"Als
   administrator uitvoeren"**.
2. Navigeer naar de projectmap en start:

```bash
python ethernet_messenger_windows.py
```

(Gebruik je een venv, activeer die eerst: `venv\Scripts\activate`.)

Als het programma niet met voldoende rechten draait, toont de applicatie
zelf een duidelijke waarschuwing met deze instructie.

> Let op: zorg dat Npcap geïnstalleerd is vóórdat je het programma start
> — zonder Npcap kan Scapy geen raw frames bouwen/versturen/sniffen, ook
> niet als Administrator.

## Gebruiksscenario: twee studenten, elk op hun eigen Windows-laptop

Variant op het scenario uit de hoofd-README, nu zonder CML/VM's:

1. Twee studenten verbinden hun laptops met hetzelfde geïsoleerde
   netwerk — bijv. beiden op de mobiele hotspot van één telefoon, een
   eigen (afgeschermde) switch in het lokaal, of een los VLAN op het
   schoolnetwerk dat de docent daarvoor heeft klaargezet.
2. Beide studenten starten `ethernet_messenger_windows.py` **als
   Administrator** en selecteren bij **Instellingen → Interface** de
   Wi-Fi- of Ethernet-adapter die met dat gedeelde netwerk verbonden is
   (niet de VPN- of virtuele adapters die Windows vaak ook toont).
3. Student A schakelt op het tabblad **Ontvangen** de sniffer in.
4. Student B kopieert Student A's MAC-adres (te zien in Student A's
   statusbalk-omgeving, of via `ipconfig /all` op Student A's laptop),
   vult dat in als Destination MAC — of gebruikt de broadcast-knop — en
   verstuurt een bericht.
5. Student A ziet het frame verschijnen in de framegeschiedenis, met
   dezelfde visuele weergave als Student B tijdens het opbouwen zag.
6. Vervolgens kunnen ze, net als in het Linux-scenario, doorgroeien naar
   Mode-B (ARP: MAC-adres opzoeken via IP), Mode-C (IPv4, genest in het
   Data-vak) en Mode-D (IPv6) — zie de hoofd-README voor de volledige
   uitleg per modus.

Werken twee studenten op verschillende OS'en (de een Linux/CML, de ander
Windows) samen op hetzelfde netwerksegment? Dat kan gewoon: beide
programma's bouwen en lezen exact hetzelfde soort frames, dus een
student op Windows en een student op Linux kunnen elkaar berichten
sturen en ontvangen.

## Bekende beperkingen (Windows-specifiek)

- De "fysieke interface"-herkenning is een trefwoord-heuristiek (zie
  hierboven) en dus minder betrouwbaar dan op Linux. Controleer altijd
  even welke interface geselecteerd is voor je gaat versturen/sniffen.
- Sommige zakelijke laptops/antivirussoftware blokkeren Npcap-installatie
  of raw-socketgebruik via groepsbeleid; overleg in dat geval met de
  systeembeheerder van de school, of gebruik de Linux-versie in CML.
- Windows Defender Firewall bemoeit zich normaal gesproken niet met raw
  Layer 2-verkeer via Npcap, maar bij problemen is het een van de eerste
  dingen om te controleren.
- Zie ook de algemene "Beperkingen" in [`README.md`](README.md#beperkingen)
  (EtherTypes onder `0x0600`, enz.) — die gelden hier net zo goed.

## Herkomst

Zelfde herkomst als de Linux-versie — zie
[`README.md`](README.md#herkomst) en [`CONVERSATION.md`](CONVERSATION.md).
Deze Windows-variant is toegevoegd naar aanleiding van het verzoek om een
aanvullende versie voor studentlaptops.
