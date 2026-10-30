# ConMgr

Plattformübergreifender Verbindungsmanager (macOS, Linux, Windows) für **SSH, SFTP, RDP und VNC**, geschrieben in Rust mit [egui/eframe](https://github.com/emilk/egui).

## Bauen & Starten

```bash
cargo run --release                     # Standard-Speicherort
cargo run --release -- ./meine.json     # eigene Verbindungsdatei
cargo test
```

### macOS: als App bauen

Unter macOS braucht ConMgr für Verbindungen ins lokale Netz die Berechtigung **„Lokales Netzwerk“**. Mit `cargo run` aus einem fremden Terminal (z. B. dem einer IDE) gilt dessen Berechtigung, und Verbindungen zu `192.168.x.x` scheitern mit „No route to host“. Deshalb als eigene App bauen und starten:

```bash
./scripts/bundle-macos.sh
open target/release/bundle/ConMgr.app
```

Beim ersten Verbinden fragt macOS einmal nach; die Freigabe lässt sich unter *Systemeinstellungen → Datenschutz & Sicherheit → Lokales Netzwerk* ändern.

## Verbindungsdatei

Standardpfad:

| OS      | Pfad |
|---------|------|
| macOS   | `~/Library/Application Support/ConMgr/connections.json` |
| Linux   | `~/.config/conmgr/connections.json` |
| Windows | `%APPDATA%\ConMgr\config\connections.json` |

Lesbares JSON – nur die Passwörter sind verschlüsselt. Die Einträge bilden einen Baum aus Ordnern, Verbindungen und Zugangsdaten (Format 2; Dateien im alten Format 1 werden beim Öffnen automatisch übernommen):

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

- **Baum** links: Ordner auf-/zuklappen, Einträge per **Ziehen & Ablegen** verschieben (auf einen Ordner = hinein, auf einen Eintrag = davor, auf die freie Fläche = oberste Ebene). **Rechtsklick** öffnet das Kontextmenü, **Doppelklick** verbindet.
- **Zugangsdaten** sind eigene Einträge. Eine Verbindung nutzt entweder *eigene* Zugangsdaten, *bestimmte* gespeicherte Zugangsdaten oder *erbt* sie vom nächsten übergeordneten Ordner, dem Zugangsdaten zugewiesen sind.
- **Icons & Farben** pro Eintrag, **Favoriten** (⭐) mit Filter, **Suche** über Name, Host und Benutzer.
- `⌘S` / `Strg+S` speichert den offenen Eintrag.

## SSH in Tabs

SSH-Verbindungen öffnen sich per Doppelklick als Tab direkt in ConMgr (eingebautes Terminal, `xterm-256color`). „Extern“ bzw. *In externem Terminal öffnen* startet stattdessen das System-`ssh`.

- **Anmeldung:** zuerst unverschlüsselte Standardschlüssel aus `~/.ssh` (`id_ed25519`, `id_ecdsa`, `id_rsa`), dann das hinterlegte Passwort, dann Keyboard-Interactive mit dem Passwort.
- **Host-Keys:** werden gegen `~/.ssh/known_hosts` geprüft (dieselbe Datei wie OpenSSH). Unbekannte Keys zeigt ConMgr mit Fingerabdruck zur Bestätigung an und trägt sie danach ein; **geänderte Keys werden immer abgelehnt**.
- **Bedienung:** Markieren mit der Maus und `⌘C` kopiert, `⌘V` fügt ein (unter Windows/Linux `Strg+C` ohne Markierung = Abbruch-Signal). Mausrad blättert im Verlauf (5000 Zeilen). Das Terminal passt seine Größe dem Fenster an.
- Beendete Sitzungen lassen sich im Tab neu verbinden. **Sperren trennt alle Sitzungen.**

Noch nicht eingebettet: SSH-Agent, verschlüsselte Schlüssel (Passphrase), SFTP, RDP und VNC – diese laufen weiterhin über die externen Clients.

Ende-zu-Ende-Test gegen einen echten sshd (HOME auf ein Testverzeichnis mit Schlüssel in `.ssh` setzen):

```bash
CONMGR_E2E_SSH_PORT=2222 HOME=/pfad/zum/test-home cargo test e2e -- --ignored
```

## Verschlüsselung

- Aus dem **Master-Passwort** wird per **Argon2id** (zufälliges Salt) ein 256-Bit-Schlüssel abgeleitet.
- Jedes Passwort wird mit **AES-256-GCM** und eigener Zufalls-Nonce verschlüsselt; die ID des Eintrags ist Associated Data, verschlüsselte Passwörter lassen sich also nicht zwischen Einträgen vertauschen.
- `verifier` ist ein verschlüsselter bekannter Text, mit dem das Master-Passwort beim Entsperren geprüft wird.
- Der Schlüssel liegt nur im Speicher und wird beim Sperren/Beenden genullt. Die Datei wird atomar und (Unix) mit Rechten `0600` geschrieben.

## Externe Clients

ConMgr startet die Clients des Betriebssystems:

| Typ  | macOS | Linux | Windows |
|------|-------|-------|---------|
| SSH  | `ssh` in Terminal.app | `ssh` im Terminal-Emulator | `ssh` (OpenSSH-Client) |
| SFTP | `sftp` in Terminal.app | `sftp` im Terminal-Emulator | `sftp` |
| RDP  | `.rdp`-Datei → „Windows App“ | `xfreerdp3`/`xfreerdp` (mit Passwort) | `mstsc` (Passwort via `cmdkey`) |
| VNC  | Bildschirmfreigabe (`vnc://`) | `vncviewer` | `vncviewer` (TigerVNC) |

**SSH/SFTP:** ConMgr übergibt das Passwort über `SSH_ASKPASS` (OpenSSH ≥ 8.4). Die App vergibt pro Verbindung ein einmaliges, 2 Minuten gültiges Token und liefert das Passwort über einen nur lokal erreichbaren Socket (127.0.0.1) an ssh – es steht weder auf der Kommandozeile noch in einer Datei. Andere Rückfragen (Host-Key bestätigen, Schlüssel-Passphrase, erneute Eingabe nach falschem Passwort) erscheinen ganz normal im Terminal.

Wo der Client kein Passwort übernehmen kann (VNC, RDP unter macOS), kopiert ConMgr es beim Verbinden in die Zwischenablage und löscht es dort nach 30 Sekunden wieder.

Hinweis Windows/RDP: `cmdkey` legt die Anmeldedaten dauerhaft in der Windows-Anmeldeinformationsverwaltung ab.
