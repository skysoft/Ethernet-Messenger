# Ethernet Messenger

Een educatieve GUI-tool voor het versturen en ontvangen van ruwe Ethernet
frames op basis van MAC-adressen (Layer 2, geen IP-laag nodig). Gebouwd
voor CCNA-onderwijs op het MBO ICT, zodat studenten met eigen ogen kunnen
zien hoe Ethernet framing, MAC-adressering en EtherType werken.

> ⚠️ **Waarschuwing:** deze tool is uitsluitend bedoeld voor gecontroleerde
> lab- en testomgevingen (bijv. een Cisco Modeling Labs (CML) topologie of
> een geïsoleerd VLAN in een oefenlokaal). Gebruik deze tool **nooit** op
> productienetwerken. Het versturen van ruwe Ethernet frames met een
> handmatig bepaald source MAC-adres (MAC-spoofing) kan netwerken
> verstoren en is op de meeste netwerken zonder toestemming niet
> toegestaan.

## Functionaliteit

- Overzichtelijke indeling in twee tabbladen, **Verzenden** en
  **Ontvangen**. Instellingen die voor beide kanten gelden (interface en
  modus) staan in de menubalk onder **Instellingen**, met de actief
  gekozen interface en modus altijd zichtbaar in de statusbalk onderin
  het venster.
- Interface-selectie (**Instellingen → Interface**) met automatische
  detectie van het eigen MAC-adres. De loopback-interface (`lo`) wordt
  niet getoond, en standaard wordt de eerste fysieke netwerkinterface
  geselecteerd (dus geen virtuele interfaces zoals `docker0`, bridges of
  veth-paren).
- **Modus-keuze (Mode-A t/m Mode-D)** (**Instellingen → Modus**): bepaalt
  welke protocol-opties beschikbaar zijn bij het opbouwen van een frame.
  Mode-A (standaard) komt overeen met de bestaande Ethernet-werking
  (vast EtherType `0x88B5`). Vanaf Mode-B verschijnt er in plaats van het
  vaste EtherType-label een keuzelijst met extra protocollen (Mode-B:
  + ARP, Mode-C: + IPv4, Mode-D: + IPv6). Ethernet én ARP kunnen
  daadwerkelijk verzonden worden; IPv4/IPv6 staan er voorlopig alleen
  ter illustratie bij (nog niet functioneel — dat komt in een latere
  fase). Ontvangen frames blijven, ongeacht de gekozen modus, altijd
  gefilterd op EtherType `0x88B5`: verzonden ARP-frames zijn dus wel op
  de kabel te zien (bijv. met Wireshark) maar nog niet in de sniffer
  van deze applicatie.
- **ARP opbouwen (Mode-B en hoger, EtherType ARP gekozen)**: onder de
  EtherType-keuzelijst verschijnen dan twee extra velden: "Soort ARP"
  ("Verzend ARP aanvraag" of "Verzend ARP antwoord") en een vrij
  IP-adresveld. De Destination MAC en Payload worden hierbij automatisch
  bepaald (die velden worden tijdelijk uitgeschakeld):
  - **ARP aanvraag**: Destination MAC wordt broadcast
    (`ff:ff:ff:ff:ff:ff`), payload wordt `Wie heeft IP adres <IP>,
    vertel het mij.` — waarbij "mij" verwijst naar het Source MAC-adres
    dat in het frame te zien is.
  - **ARP antwoord**: Destination MAC blijft handmatig invulbaar (een
    antwoord is immers gericht aan één specifieke aanvrager), payload
    wordt `IP-adres <IP> hoort bij mij.`

  Dit is een **leesbare pseudo-ARP-tekst** ter illustratie van wat een
  ARP-bericht betekent, geen bit-exacte reconstructie van de echte
  (binaire) ARP-pakketstructuur uit RFC 826.
- Ethernet frame opbouwen: source MAC (auto-ingevuld, aanpasbaar),
  destination MAC (met snelknop voor broadcast `ff:ff:ff:ff:ff:ff`),
  EtherType (in Mode-A vast op `0x88B5`), vrije tekst payload.
- Versturen van het frame via Scapy's `sendp()`.
- Live visuele weergave van het op te bouwen Ethernet frame (Preamble,
  Destination/Source MAC, Type, Data, FCS) die meebeweegt terwijl je de
  velden invult. Elk veld toont de daadwerkelijke waarde in het vet
  (bijv. de ingetypte destination MAC of payloadtekst), met de veldnaam
  er klein onder — zo is in één oogopslag te zien wat er verstuurd wordt
  én hoe dat in de framestructuur past. Preamble en FCS zijn grijs
  gemarkeerd ter illustratie (in werkelijkheid door de netwerkkaart
  toegevoegd resp. berekend, niet door deze applicatie): Preamble toont
  het standaard bitpatroon, en de getoonde FCS is een illustratieve
  CRC-32-checksum over de huidige frame-inhoud die dus verandert zodra
  je iets aanpast — precies zoals een echte FCS.
- Live sniffer (aan/uit via checkbox) die uitsluitend inkomende frames met
  EtherType `0x88B5` toont (gefilterd met een BPF-filter, zodat er geen
  ruis van ARP/IPv4/IPv6/STP/LLDP-verkeer binnenkomt). Zolang er nog
  niets is ontvangen, toont de visualisatie geen frame-inhoud (dus ook
  geen nagemaakte Preamble/Type/FCS) — pas na het eerste ontvangen
  frame worden de velden echt ingevuld.
- **Eigen verzonden frames worden niet in de sniffer getoond.** Een
  lokale raw-socket capture (zoals Scapy/tcpdump gebruikt) vangt op
  Linux normaal gesproken zowel inkomend als zelf verzonden verkeer af
  op dezelfde interface — dat gebeurt in de kernel, niet omdat een
  switch het frame terugstuurt (een switch stuurt een frame nooit terug
  de poort op waar het vandaan kwam, ook niet bij een broadcast). Om de
  sniffer realistisch te houden — zodat hij toont wat een *andere*
  computer op het netwerk zou zien — filtert de applicatie frames eruit
  waarvan het source MAC-adres overeenkomt met dat van de eigen
  interface.
- **Geschiedenislijst van ontvangen frames**: elk ontvangen frame met
  EtherType `0x88B5` verschijnt in een lijst; door een frame in die lijst
  aan te klikken wordt de visualisatie bijgewerkt met de inhoud van dát
  frame, zodat je kunt terugkijken naar eerder ontvangen frames. Nieuwe
  frames worden automatisch geselecteerd zodra ze binnenkomen. De
  visualisatie is **exact dezelfde weergave** als aan de verzendkant —
  inclusief een FCS die opnieuw berekend is uit de ontvangen inhoud —
  zodat de verzendende en ontvangende student precies hetzelfde frame
  zien. Met "Lijst wissen" leeg je de geschiedenis (de visualisatie
  keert dan terug naar de lege staat). Een klein logvenster eronder
  houdt een beknopte, doorlopende geschiedenis bij (met tijdstip).
- **"Open geselecteerd frame in Wireshark"**: schrijft het in de lijst
  geselecteerde frame weg als tijdelijk `.pcap`-bestand (via Scapy's
  `wrpcap()`) en opent dat direct in Wireshark (`wireshark -r <bestand>`),
  zodat studenten hetzelfde frame ook met de vertrouwde protocol-analyse
  van Wireshark kunnen bekijken. Vereist dat Wireshark op het systeem
  geïnstalleerd is (`sudo apt install wireshark`); zo niet, dan toont de
  applicatie een duidelijke foutmelding met installatie-instructie.
- De payload wordt bij verzending voorafgegaan door een 2-byte lengteveld,
  zodat de ontvanger altijd exact de ingetypte tekst kan reconstrueren.
  Ethernet vult frames die korter zijn dan de minimale framegrootte
  (60 bytes exclusief FCS) automatisch aan met nulbytes; in de visuele
  weergave is dat te zien doordat het Data-vak (met zijn werkelijke
  bytegrootte erboven) breder is dan de daadwerkelijk ingetypte tekst.
- Duidelijke foutafhandeling: waarschuwing wanneer het programma niet als
  root draait, met instructies om dit op te lossen.

## Vereisten

- Debian 13 met KDE Plasma
- Python 3
- PyQt6
- Scapy
- Root-rechten (of `setcap`-configuratie) voor raw sockets
- Wireshark (optioneel, voor de knop "Open geselecteerd frame in
  Wireshark"): `sudo apt install wireshark`

## Installatie op Debian 13

### Optie A: systeembreed met apt + pip

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-pyqt6
sudo pip install --break-system-packages scapy
```

### Optie B: via een virtuele omgeving (venv)

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv python3-pyqt6

cd Ethernet-Messenger
python3 -m venv --system-site-packages venv
source venv/bin/activate
pip install scapy
```

> `--system-site-packages` is nodig zodat de venv toegang heeft tot de
> systeem-brede PyQt6-installatie (PyQt6 via pip is zwaar en vereist vaak
> extra systeemafhankelijkheden; via apt is eenvoudiger op Debian).

## Starten

Raw sockets (nodig om ruwe Ethernet frames te bouwen, versturen en te
sniffen) vereisen verhoogde rechten. Er zijn twee manieren om dit te
regelen:

### Optie 1: starten met sudo

```bash
sudo python3 ethernet_messenger.py
```

### Optie 2: capabilities toekennen aan de Python-interpreter (setcap)

Handig als je het programma niet als root wilt draaien (bijvoorbeeld
binnen KDE Plasma zonder een GUI-app als root te starten):

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
python3 ethernet_messenger.py
```

> Let op: dit geeft de systeembrede `python3`-interpreter permanente
> netwerkrechten. Overweeg dit alleen te doen op een dedicated lab-VM, en
> niet op een interpreter die ook voor andere doeleinden gebruikt wordt.
> Gebruik je een venv, pas dan `setcap` toe op de python-executable binnen
> de venv (`venv/bin/python3`).

Als het programma niet met voldoende rechten draait, toont de applicatie
zelf een duidelijke waarschuwing met bovenstaande instructies.

## Gebruiksscenario: twee studenten in een lab

Een veelvoorkomend scenario binnen een CCNA-les:

1. Twee studenten (Student A en Student B) krijgen elk een virtuele
   machine binnen dezelfde CML-topologie, verbonden via een gedeelde
   switch of hetzelfde geïsoleerde VLAN (bijv. VLAN 999, uitsluitend voor
   labdoeleinden).
2. Beide studenten starten `ethernet_messenger.py` op hun VM en
   selecteren de netwerkinterface die met het labsegment verbonden is.
3. Student A schakelt de sniffer in en laat deze meeluisteren.
4. Student B vult in het destination MAC-veld het MAC-adres van Student
   A's interface in (zichtbaar te vinden via `ip link show` op Student
   A's machine, of via de broadcast-knop om eerst een broadcast-frame te
   sturen zodat iedereen op het segment het frame ziet), typt een
   boodschap in het payload-veld en klikt op "Frame versturen".
5. Student A ziet in het logvenster van de sniffer het binnenkomende
   frame verschijnen: source MAC, destination MAC, EtherType `0x88B5` en
   de payload-tekst.
6. Dit maakt tastbaar hoe Ethernet-framing werkt zonder tussenkomst van
   IP, ARP of een hogere laag — precies wat er "onder" IP gebeurt.

Docenten kunnen dit uitbreiden door studenten te laten experimenteren met
een afwijkend EtherType, ongeldige MAC-adressen, of door Wireshark
ernaast te laten meekijken op hetzelfde labsegment.

## Beperkingen

- Deze tool werkt alleen op Ethernet-achtige interfaces die raw sockets
  ondersteunen (dus niet op interfaces waar dit door de OS/virtualisatie
  wordt geblokkeerd).
- Frames met een EtherType lager dan `0x0600` worden door sommige
  netwerkkaarten/drivers als IEEE 802.3-lengteveld geïnterpreteerd in
  plaats van als EtherType; gebruik bij voorkeur waarden vanaf `0x0600`.

## Herkomst

Deze applicatie is gebouwd door de docent (Mondriaan ICT, GitHub: `skysoft`)
in samenwerking met [Claude Code](https://claude.com/claude-code), Anthropic's
AI-coding-assistent. Wie wil weten hoe de applicatie stap voor stap tot
stand is gekomen — welke verzoeken tot welke wijzigingen hebben geleid —
kan dat teruglezen in [`CONVERSATION.md`](CONVERSATION.md).
