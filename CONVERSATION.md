# Ontwikkelgesprek — Ethernet Messenger

Dit document is een door Claude gereconstrueerde samenvatting van het gesprek
waarin deze applicatie stap voor stap is gebouwd en uitgebreid. Het is **geen
letterlijke, woord-voor-woord transcript-export** (die faciliteit was niet
beschikbaar), maar een chronologisch overzicht van elk verzoek en wat daarop
is gebouwd, bedoeld als ontwikkelgeschiedenis/changelog in gespreksvorm.

> Let op: deze repository is **public**. Dit document bevat de context en
> beslissingen achter de code, maar geen wachtwoorden, tokens of andere
> gevoelige gegevens.

---

## 1. Initiële opdracht

**Verzoek:** Bouw "Ethernet Messenger" — een educatieve GUI-tool voor het
versturen en ontvangen van ruwe Ethernet frames op basis van MAC-adressen,
bedoeld voor CCNA-onderwijs (MBO ICT). Platform: Debian 13 + KDE Plasma,
Python 3 + PyQt6 + Scapy. Vereisten: interface-selectie met MAC-detectie,
frame-opbouw (source/destination MAC, EtherType 0x88B5, payload), versturen
via `sendp()`, een live sniffer in een aparte thread, root-rechten-check met
duidelijke foutmelding, volledig Nederlandstalige UI, en een README met
installatie-instructies en een lab-scenario voor twee studenten.

**Resultaat:** `ethernet_messenger.py` en `README.md` gebouwd. Vervolgens is
GitHub CLI geïnstalleerd, ingelogd via device-flow, en is de public repo
`Ethernet-Messenger` aangemaakt met een initiële commit.

## 2. Sniffer verfijnen

**Verzoek:** Toon in de sniffer alleen frames met EtherType 0x88B5, decodeer
ontvangen frames leesbaar voor een mens, kies standaard de eerste fysieke
interface, en laat de loopback-interface weg.

**Resultaat:** BPF-filter (`ether proto 0x88b5`) toegevoegd aan de sniffer,
mensleesbare decodering (MAC-classificatie, EtherType, framegrootte,
payload als tekst/hex), loopback-detectie via `/sys/class/net/<iface>/flags`,
en detectie van fysieke interfaces via `/sys/class/net/<iface>/device`.

## 3. Pull van GitHub

**Verzoek:** Pull een nieuwe kopie van de app van GitHub.

**Resultaat:** Lokale map bleek al synchroon; een `git fetch` bevestigde dit
expliciet aan de gebruiker.

## 4. Payload en padding

**Verzoek:** De payload moet zoals ingetypt door de verzender ook zo in het
decodeervenster getoond worden; "verborgen" padding niet tonen, wel een hint
met het aantal bytes.

**Resultaat:** Een 2-byte lengteveld toegevoegd vóór de payload
(`bouw_payload_bytes()` / `ontleed_payload()`), zodat de ontvanger exact de
ingetypte tekst kan reconstrueren en de padding apart kan tonen als
"X bytes (niet getoond)".

## 5. Live visuele frameweergave (verzendkant)

**Verzoek:** Toon een grafische weergave van het te verzenden Ethernet frame
(Preamble, Destination/Source Address, Type, Data, FCS met byte-lengtes),
live tijdens het intypen.

**Resultaat:** `FrameVisualisatieWidget` (QPainter) gebouwd: proportionele
vakken per veld, Preamble/FCS grijs gemarkeerd als niet door de applicatie
zelf gebouwd.

## 6. Waarde/naam wisselen + echte FCS

**Verzoek:** Wissel in de visualisatie de veldnamen en de werkelijke waarden
om (waarde vet in het vak, naam klein eronder). Vervang "(door
netwerkkaart)" door dummy data. Genereer bij elke wijziging nieuwe dummy data
in het FCS-veld.

**Resultaat:** Preamble toont het standaard bitpatroon (`AA...AB`), Data
toont de echte ingetypte tekst, en FCS is een echte CRC-32-checksum
(`bereken_dummy_fcs()`) over de huidige frame-inhoud — verandert dus
automatisch bij elke aanpassing, identiek aan hoe een echte FCS werkt.

## 7. Nogmaals pull van GitHub

**Verzoek:** Pull een nieuwe kopie van de app van GitHub.

**Resultaat:** Er bleek buiten de sessie om een commit gepusht te zijn
("Length field changed to accomodate preamble", de breedte-cap van 60 naar
30 aangepast). Deze is bekeken en gepulld.

## 8. Dezelfde visuele weergave aan ontvangstkant

**Verzoek:** Vervang de tekstuele sniffer-decodering door dezelfde visuele
weergave als aan de verzendkant, zodat het frame voor de verzendende en
ontvangende student identiek is.

**Resultaat:** Een tweede `FrameVisualisatieWidget`-instantie aan de
ontvangstkant, gevoed door de daadwerkelijk ontvangen bytes; de ontvanger
herberekent zijn eigen FCS uit de ontvangen inhoud, wat bij een ongewijzigd
frame identiek is aan wat de verzender toonde (offscreen geverifieerd).

## 9. Tabbladen

**Verzoek:** Te veel op één scherm — maak twee tabbladen, "Verzenden" en
"Ontvangen", en verdeel de UI daarover.

**Resultaat:** `QTabWidget` met twee tabs; interface-selectie blijft erboven
(geldt voor beide kanten).

## 10. Drie upgrades tegelijk

**Verzoek (drieledig):**
1. Vul pas na het eerste ontvangen frame de velden echt in (geen nep-Preamble/Type/FCS vooraf).
2. Maak een klikbare lijst van alle ontvangen frames; klikken laadt dat frame in de visualisatie (terugkijken).
3. Introduceer een modus-systeem ("Mode-A" = alleen Ethernet, zoals nu; Mode-B/C/D voegen respectievelijk ARP, IPv4, IPv6 toe als *zichtbare* opties, stapsgewijs en primair visueel — nog niet volledig functioneel voor niet-Ethernet protocollen).

**Resultaat:**
- `toon_leeg()` op `FrameVisualisatieWidget` voor een realistische lege staat.
- `QListWidget` met geschiedenis; `currentRowChanged` rendert het geselecteerde frame.
- Modus-keuzelijst boven de tabs; vanaf Mode-B vervangt een protocol-combobox (via `QStackedWidget`) het vaste EtherType-label. Versturen van iets anders dan Ethernet toont een duidelijke "nog niet beschikbaar"-melding; de sniffer blijft altijd gefilterd op 0x88B5.

## 11. Fullscreen bij opstarten

**Verzoek:** Start de applicatie full-screen.

**Resultaat:** `venster.showMaximized()` — venster gemaximaliseerd, titelbalk
en vensterbediening blijven zichtbaar (geen randloze fullscreen).

## 12. Fix: maximaliseren werkte niet

**Verzoek:** Getest op Debian/KDE — het venster start niet gemaximaliseerd;
titelbalk moet behouden blijven.

**Resultaat:** `showMaximized()` direct vóór `app.exec()` wordt door sommige
window managers genegeerd omdat het venster dan nog niet bij de WM
geregistreerd is. Opgelost met `QTimer.singleShot(0, venster.showMaximized)`,
zodat de maximalisatie pas gebeurt zodra de event-loop draait.

## 13. Vraag: is het realistisch dat je eigen broadcast in de sniffer verschijnt?

**Vraag:** Als een student een broadcast verstuurt terwijl de sniffer aan
staat, verschijnt die broadcast ook in de lijst van diezelfde computer. Is
dat realistisch?

**Antwoord:** Nee, niet op de kabel/switch — een switch stuurt een frame
nooit terug de poort op waar het vandaan kwam, ook niet bij een broadcast.
Wat hier gebeurde is een bekend kenmerk van lokale raw-socket/packet-capture
op Linux (Scapy/tcpdump vangen op dezelfde interface standaard zowel
inkomend als zelf verzonden verkeer af, in de kernel — niet omdat het over
het netwerk terugkomt).

**Gekozen aanpak:** eigen verzonden frames volledig filteren uit de sniffer,
zodat die laat zien wat een *andere* computer op het netwerk zou zien.

**Resultaat:** `SnifferThread` onthoudt het eigen MAC-adres (`get_if_hwaddr`)
en negeert in `_verwerk_frame()` elk frame met dat source MAC-adres.
Geverifieerd: eigen frames (ook met afwijkende hoofdlettering) worden
geblokkeerd, frames van andere machines komen gewoon door.

## 14. Dit document

**Verzoek:** Maak `CONVERSATION.md` en push naar de repo.

**Resultaat:** Dit bestand.

---

*Elke stap hierboven is telkens gevolgd door een syntax-check
(`py_compile`) en, waar mogelijk, een offscreen functionele test (tijdelijke
installatie van PyQt6/Scapy op de ontwikkelmachine, gerenderd via
`QT_QPA_PLATFORM=offscreen`) voordat de wijziging gecommit en gepusht werd.*
