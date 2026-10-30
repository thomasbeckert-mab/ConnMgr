<p align="center"><img src="assets/logo.svg" width="128" alt="ConnMgr-Logo"></p>

# ConnMgr

Plattformübergreifender Verbindungsmanager (macOS, Linux, Windows) für **SSH, SFTP, RDP und VNC**, geschrieben in Rust mit [egui/eframe](https://github.com/emilk/egui). Oberfläche auf **Deutsch und Englisch**, hell, dunkel oder wie das Betriebssystem.

## Bauen & Starten

```bash
cargo run --release                     # Standard-Speicherort
cargo run --release -- ./meine.json     # eigene Verbindungsdatei
cargo test
```

### macOS: als App bauen

Unter macOS braucht ConnMgr für Verbindungen ins lokale Netz die Berechtigung **„Lokales Netzwerk“**. Mit `cargo run` aus einem fremden Terminal (z. B. dem einer IDE) gilt dessen Berechtigung, und Verbindungen zu `192.168.x.x` scheitern mit „No route to host“. Deshalb als eigene App bauen und starten:

```bash
./scripts/bundle-macos.sh
open target/release/bundle/ConnMgr.app
```

Beim ersten Verbinden fragt macOS einmal nach; die Freigabe lässt sich unter *Systemeinstellungen → Datenschutz & Sicherheit → Lokales Netzwerk* ändern.

Damit die Freigabe über Neubauten erhalten bleibt, einmalig ein lokales Signatur-Zertifikat anlegen (selbst signiert, nur für `codesign`, im Anmelde-Schlüsselbund):

```bash
./scripts/create-signing-cert-macos.sh
```

`bundle-macos.sh` signiert dann damit; ohne Zertifikat signiert es ad-hoc, und macOS verwirft die Freigabe bei jedem Neubau.

### Umbenennung ConMgr → ConnMgr

Bis Oktober 2026 hieß die App „ConMgr“. Beim ersten Start übernimmt ConnMgr den alten Datenordner (`…/ConMgr` → `…/ConnMgr`) samt Verbindungsdatei und gemerkten RDP-Zertifikaten. Unverändert bleiben bewusst die macOS-Bundle-Kennung `app.conmgr.ConMgr` (an ihr hängt die Freigabe „Lokales Netzwerk“), der Name des Signatur-Zertifikats und der interne Prüftext des Master-Passworts.

### Logo

`assets/logo.svg` (mit runden Ecken) zeigt die App auf dem Sperrbildschirm und als Hintergrund, solange keine Sitzung offen ist, und erzeugt daraus das Fenster-Icon. Für das macOS-App-Icon gibt es `assets/icon-macos.svg`: dasselbe Motiv **randlos und ohne eigene Ecken**, denn seit macOS 26 schneidet das System die Form selbst zu und stellt Icons mit Rand verkleinert auf einer Kachel dar. `bundle-macos.sh` rendert es mit `cargo run --example render_icon` in ein Iconset und baut daraus `AppIcon.icns`. Beide Dateien bei Änderungen am Motiv gemeinsam anpassen.

## Verbindungsdatei

Standardpfad:

| OS      | Pfad |
|---------|------|
| macOS   | `~/Library/Application Support/ConnMgr/connections.json` |
| Linux   | `~/.config/connmgr/connections.json` |
| Windows | `%APPDATA%\ConnMgr\config\connections.json` |

Lesbares JSON – nur Passwörter, Schlüssel und Passphrasen sind verschlüsselt. Die Einträge bilden einen Baum aus Ordnern, Verbindungen und Zugangsdaten (Format 2; Dateien im alten Format 1 werden beim Öffnen automatisch übernommen):

```json
{
  "version": 2,
  "kdf": { "algorithm": "argon2id", "salt": "…", "m_cost": 19456, "t_cost": 2, "p_cost": 1 },
  "verifier": { "nonce": "…", "data": "…" },
  "items": [
    { "type": "folder", "id": "…", "name": "Credentials", "expanded": true, "children": [
      { "type": "credential", "id": "c1", "name": "Personal Admin", "username": "admin",
        "password": { "nonce": "…", "data": "…" } }
    ]},
    { "type": "folder", "id": "f1", "name": "Production", "color": "#e53935", "credential_id": "c1",
      "expanded": true, "children": [
      { "type": "connection", "id": "…", "name": "web01 - SSH", "host": "10.0.0.5", "port": 22,
        "protocol": "ssh", "credentials": { "mode": "inherit" }, "favorite": true }
    ]}
  ]
}
```

## Bedienung

- **Baum** links: **Doppelklick auf eine Verbindung verbindet** (ein Klick markiert) – ist schon ein Tab offen, wechselt ConnMgr dorthin („Weitere Sitzung öffnen“ im Kontextmenü öffnet eine zusätzliche). **Rechtsklick** öffnet das Kontextmenü mit Eigenschaften, Duplizieren, Exportieren und Löschen. Ein Klick auf Ordner oder Zugangsdaten markiert nur; der **Eigenschaften-Tab** öffnet sich ausschließlich über „📝 Eigenschaften“ (oder beim Anlegen) und lässt sich mit ✖ schließen. Ordner per Doppelklick auf-/zuklappen, Einträge per **Ziehen & Ablegen** verschieben (auf einen Ordner = hinein, auf einen Eintrag = davor, auf die freie Fläche = oberste Ebene).
- **⚡ Schnellverbindung** (Feld in der Werkzeugleiste, `⌘K` / `Strg+K`): Adresse eintippen und Enter – z. B. `rdp://server`, `ssh://admin@host:2222`, `vnc://host:5901`, `admin@host`, `host:3389`, `[::1]:22`. Ohne Schema entscheidet der Port (3389 = RDP, 5900–5999 = VNC, sonst SSH). Passwort (bei RDP auch Benutzer) fragt der Tab ab. **💾** im Tab speichert die Verbindung in den Baum (in den markierten Ordner); **▾** zeigt die letzten zehn Adressen (ohne Passwörter).
- **📌 Fixieren / automatisch ausblenden:** Nicht fixiert bleibt nur eine schmale Leiste (»); fährt die Maus darüber, schwebt der Baum über dem Inhalt ein und verschwindet beim Verlassen wieder – die Sitzung behält ihre Größe. Die Einstellung wird gespeichert.
- **Löschen** fragt in einem Dialog nach; **Entf** (Mac: ⌘⌫) löscht den markierten Eintrag.
- Die Statuszeile unten zeigt den Zustand der zuletzt gestarteten Verbindung und leert sich, wenn sie endet.
- **Zugangsdaten** sind eigene Einträge mit Benutzer, Passwort und optional **privatem SSH-Schlüssel samt Passphrase** (aus Datei laden oder einfügen; Fingerabdruck und „Öffentlichen Schlüssel kopieren“). Eine Verbindung nutzt *eigene* Zugangsdaten, *bestimmte* gespeicherte oder *erbt* sie vom nächsten übergeordneten Ordner mit Zugangsdaten.
- **Icons & Farben** pro Eintrag, **Favoriten** (⭐) mit Filter, **Suche** über Name, Host und Benutzer.
- **Duplizieren** kopiert Einträge und ganze Ordner; Verweise auf mitkopierte Zugangsdaten zeigen danach auf die Kopien.
- **Menü ☰:** *Master-Passwort ändern* (neues Salt, alle Geheimnisse umverschlüsselt), *Alles exportieren*, *Importieren*. Einzelne Einträge/Ordner exportiert das Kontextmenü. Exporte sind eigene, mit einem **eigenen Passwort** geschützte Dateien – gut zum Weitergeben. Importe landen in einem neuen Ordner „Import …“.
- `⌘S` / `Strg+S` speichert den offenen Eintrag.
- **⚙ Einstellungen** (Menü ☰): Sprache (wie System, Deutsch, English), Darstellung (wie System, Hell, Dunkel) und **Entsperren mit Touch ID**. Änderungen wirken sofort und werden in der Verbindungsdatei gespeichert – auch der Sperrbildschirm erscheint danach in Sprache und Design.

## Sitzungen in Tabs

Ein Doppelklick öffnet SSH, SFTP, RDP und VNC als Tab direkt in ConnMgr. „Extern“ bzw. das Kontextmenü startet stattdessen das Programm des Betriebssystems.

### SSH-Terminal

Eingebautes Terminal (`xterm-256color`, 256 Farben/Truecolor). Markieren mit der Maus und `⌘C` kopiert, `⌘V` fügt ein (unter Windows/Linux `Strg+C` ohne Markierung = Abbruch-Signal). Mausrad blättert im Verlauf (5000 Zeilen); die Größe folgt dem Fenster.

**Anmeldung** in dieser Reihenfolge:
1. privater Schlüssel aus den Zugangsdaten,
2. **SSH-Agent** (`SSH_AUTH_SOCK`; unter Windows OpenSSH-Agent und Pageant),
3. Standardschlüssel `~/.ssh/id_ed25519`, `id_ecdsa`, `id_rsa`,
4. Passwort, dann Keyboard-Interactive.

Fehlt eine **Passphrase** oder ein Passwort – oder wird das gespeicherte abgelehnt –, fragt ConnMgr im Tab nach. Akzeptiert der Server nur Schlüssel, gibt es eine klare Meldung statt einer Passwortabfrage.

**Host-Keys** werden gegen `~/.ssh/known_hosts` geprüft (dieselbe Datei wie OpenSSH). Unbekannte Keys zeigt ConnMgr mit Fingerabdruck zur Bestätigung an; **geänderte Keys werden immer abgelehnt**.

### SFTP-Browser

Für SFTP-Verbindungen per Doppelklick, für SSH-Verbindungen über „📂 SFTP“. Gleiche Anmeldung wie das Terminal. Pfadleiste, Home, Aktualisieren; Doppelklick öffnet Ordner bzw. lädt Dateien herunter. **Hochladen** per Knopf oder **Drag & Drop aus Finder/Explorer**, Übertragungen mit Fortschritt laufen nebenher. Neuer Ordner, Umbenennen, Löschen (Ordner nur, wenn leer).

### RDP

Über [IronRDP](https://github.com/Devolutions/IronRDP): TLS mit **NLA** (CredSSP/NTLM), Desktop in Tab-Größe (physische Pixel; auf Retina-Displays meldet ConnMgr Windows die passende Skalierung, z. B. 200 %). Maus inkl. Rad, Tastatur: Text geht als Unicode an den Server und ist damit unabhängig vom Tastaturlayout; Sondertasten und Kürzel als Scancodes (unter macOS wird ⌘ zu Strg, also ⌘C/⌘X/⌘V wie gewohnt).

- **Größe:** Ändert sich der Tab (Fenster, Seitenleiste), passt sich der Windows-Desktop nach einer halben Sekunde Ruhe an (Display-Control-Kanal).
- **Zwischenablage:** Text in beide Richtungen. In Windows Kopiertes landet in der Mac-Zwischenablage; auf dem Mac Kopiertes steht in Windows zum Einfügen bereit. Hinweis: Wie bei mstsc sieht der Server dabei alles, was du lokal kopierst, solange der Tab verbunden ist.

Anmeldung: Benutzer als `benutzer`, `DOMÄNE\benutzer` oder `benutzer@domäne`; fehlen Benutzer oder Passwort, fragt der Tab nach.

**Zertifikate:** RDP-Server haben meist selbst signierte Zertifikate. Lässt sich das Zertifikat nicht prüfen, zeigt ConnMgr den SHA-256-Fingerabdruck zur Bestätigung und merkt ihn sich in `rdp_certificates.json` (neben der Verbindungsdatei). **Ein geändertes Zertifikat wird abgelehnt** – Eintrag dort löschen, wenn der Server bewusst ein neues bekommen hat.

Noch nicht: Kerberos, Smartcards, Sound, Laufwerksumleitung, Dateien/Bilder in der Zwischenablage, RD-Gateway.

### VNC

Bild wird ins Fenster eingepasst; Maus (inkl. Rad) und Tastatur werden weitergegeben, `⌘V`/`Strg+V` tippt den Text der Zwischenablage auf der Gegenseite. Text aus der Zwischenablage des Servers wird übernommen. Kodierungen: ZRLE, CopyRect, Raw.

Anmeldung: klassisches **VNC-Passwort** (aus den Zugangsdaten oder per Abfrage). Die macOS-Bildschirmfreigabe verlangt standardmäßig Apple-Anmeldung (ARD), die nicht unterstützt wird – dort *„VNC-Benutzer dürfen den Bildschirm mit Passwort steuern“* aktivieren oder extern öffnen.

### Omnissa Horizon

Horizon-Desktops und -Apps laufen im **Omnissa Horizon Client** (Blast/PCoIP sind proprietär und lassen sich nicht einbetten). ConnMgr startet ihn über einen `horizon-client://`-Link nach der [Omnissa-Doku](https://docs.omnissa.com/HorizonClient-MacGuide-V2512/SyntaxforCreatingURIs):

- Felder: Connection Server, Port (Standard 443), **Desktop/App** (leer = Auswahl im Client), **Anzeigeprotokoll** (Standard, Blast, PCoIP).
- Benutzer und Domäne kommen aus den Zugangsdaten (auch geerbt); `DOMÄNE\benutzer` wird zu Benutzer + `domainName`. Eine UPN (`benutzer@firma.de`) versteht der Link nicht – dann nur der Benutzerteil.
- Ein Passwort lässt sich per Link bewusst nicht übergeben: Der Client fragt danach, ConnMgr legt es 30 s in die Zwischenablage.
- Schnellverbindung: `horizon://view.firma.de/Finance Desktop`.
- Start: macOS `open` (vorher Prüfung, ob der Horizon Client installiert ist), Windows URL-Handler, Linux `xdg-open`.

Beendete Sitzungen lassen sich im Tab neu verbinden. **Rechtsklick auf einen Tab:** Neu verbinden, Schließen, Andere schließen, Alle Verbindungen schließen. **Sperren trennt alle Sitzungen.**

### Tests gegen echte Server

Die mit `#[ignore]` markierten Tests laufen gegen einen echten sshd. `HOME` muss auf ein Testverzeichnis zeigen (Schlüssel in `.ssh`, `known_hosts` wird dort angelegt; für den Passphrase-Test zusätzlich `enc_key` mit Passphrase `geheim123`):

```bash
CONNMGR_E2E_SSH_PORT=2222 HOME=/pfad/zum/test-home cargo test e2e -- --ignored --test-threads=1
```

Der VNC-Test (eigener minimaler RFB-Server) und der RDP-Zertifikatstest (eigener Server bis einschließlich TLS) laufen bei `cargo test` immer.

## Entsperren mit Touch ID (macOS)

In den Einstellungen einschalten; beim nächsten Start fragt ConnMgr nach dem Fingerabdruck (nach manuellem Sperren per Knopf 👆). Das Master-Passwort funktioniert immer weiter, „Passwort eingeben“ in der Touch-ID-Abfrage führt dorthin.

- Im **Anmelde-Schlüsselbund** liegt der Schlüssel der Verbindungsdatei (nicht das Master-Passwort), nur für ConnMgr ohne Rückfrage lesbar.
- **Einschränkung:** Einträge, bei denen macOS selbst den Fingerabdruck erzwingt, sind Apps mit Apple-Developer-ID vorbehalten (sonst Fehler -34018). Hier erzwingt ConnMgr die Abfrage; ein Schadprogramm, das bereits unter deinem Benutzer läuft und die Signatur von ConnMgr fälscht, käme ohne Fingerabdruck an den Schlüssel.
- Ändert sich das Master-Passwort, wird der gespeicherte Schlüssel mitgezogen; passt er nicht mehr (z. B. Datei woanders geändert), verwirft ConnMgr ihn und verlangt das Passwort.

## Verschlüsselung

- Aus dem **Master-Passwort** wird per **Argon2id** (zufälliges Salt) ein 256-Bit-Schlüssel abgeleitet.
- Jedes Geheimnis (Passwort, privater Schlüssel, Passphrase) wird einzeln mit **AES-256-GCM** und eigener Zufalls-Nonce verschlüsselt. Associated Data ist die ID des Eintrags plus das Feld – Chiffrate lassen sich weder zwischen Einträgen noch zwischen Feldern vertauschen.
- `verifier` ist ein verschlüsselter bekannter Text, mit dem das Master-Passwort beim Entsperren geprüft wird.
- Der Schlüssel liegt nur im Speicher und wird beim Sperren/Beenden genullt. Die Datei wird atomar und (Unix) mit Rechten `0600` geschrieben.

## Externe Clients

Über „Extern“ (bei RDP immer) startet ConnMgr die Clients des Betriebssystems:

| Typ  | macOS | Linux | Windows |
|------|-------|-------|---------|
| SSH  | `ssh` in Terminal.app | `ssh` im Terminal-Emulator | `ssh` (OpenSSH-Client) |
| SFTP | `sftp` in Terminal.app | `sftp` im Terminal-Emulator | `sftp` |
| RDP  | `.rdp`-Datei → „Windows App“ | `xfreerdp3`/`xfreerdp` (mit Passwort) | `mstsc` (Passwort via `cmdkey`) |
| VNC  | Bildschirmfreigabe (`vnc://`) | `vncviewer` | `vncviewer` (TigerVNC) |

**SSH/SFTP:** ConnMgr übergibt das Passwort über `SSH_ASKPASS` (OpenSSH ≥ 8.4). Die App vergibt pro Verbindung ein einmaliges, 2 Minuten gültiges Token und liefert das Passwort über einen nur lokal erreichbaren Socket (127.0.0.1) an ssh – es steht weder auf der Kommandozeile noch in einer Datei. Andere Rückfragen (Host-Key bestätigen, Schlüssel-Passphrase, erneute Eingabe nach falschem Passwort) erscheinen ganz normal im Terminal.

Wo der Client kein Passwort übernehmen kann (VNC, RDP unter macOS), kopiert ConnMgr es beim Verbinden in die Zwischenablage und löscht es dort nach 30 Sekunden wieder.

Hinweis Windows/RDP: `cmdkey` legt die Anmeldedaten dauerhaft in der Windows-Anmeldeinformationsverwaltung ab.
