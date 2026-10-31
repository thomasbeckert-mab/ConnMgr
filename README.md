<p align="center"><img src="assets/logo.svg" width="128" alt="ConnMgr logo"></p>

# ConnMgr

Cross-platform connection manager (macOS, Linux, Windows) for **SSH, SFTP, RDP, VNC and Omnissa Horizon**, written in Rust with [egui/eframe](https://github.com/emilk/egui). The UI is available in **English and German**, in light or dark mode or following the operating system.

## Build & run

```bash
cargo run --release                     # default location
cargo run --release -- ./my.json        # custom connection file
cargo test
```

### macOS: build as an app

On macOS, ConnMgr needs the **"Local Network"** permission to connect to hosts on the local network. When started with `cargo run` from another app's terminal (e.g. an IDE), that app's permission applies, and connections to `192.168.x.x` fail with "No route to host". So build and launch it as its own app:

```bash
./scripts/bundle-macos.sh
open target/release/bundle/ConnMgr.app
```

macOS asks once on the first connection; the permission can be changed under *System Settings → Privacy & Security → Local Network*.

To keep the permission across rebuilds, create a local code-signing certificate once (self-signed, for `codesign` only, stored in the login keychain):

```bash
./scripts/create-signing-cert-macos.sh
```

`bundle-macos.sh` then signs with it. Without the certificate it signs ad hoc, and macOS drops the permission on every rebuild.

### Rename ConMgr → ConnMgr

Until October 2026 the app was called "ConMgr". On first start, ConnMgr takes over the old data folder (`…/ConMgr` → `…/ConnMgr`) including the connection file and remembered RDP certificates. Deliberately unchanged: the macOS bundle identifier `app.conmgr.ConMgr` (the "Local Network" permission is tied to it), the name of the signing certificate, and the internal verifier text of the master password.

### Logo

`assets/logo.svg` (with rounded corners) is shown on the lock screen and as the background while no session is open, and is also rendered into the window icon. The macOS app icon uses `assets/icon-macos.svg`: the same motif **full-bleed and without its own corners**, because since macOS 26 the system applies the shape mask itself and shows icons with a margin shrunk onto a tile. `bundle-macos.sh` renders it into an iconset with `cargo run --example render_icon` and builds `AppIcon.icns` from it. Update both files together when the motif changes.

## Connection file

Default path:

| OS      | Path |
|---------|------|
| macOS   | `~/Library/Application Support/ConnMgr/connections.json` |
| Linux   | `~/.config/connmgr/connections.json` |
| Windows | `%APPDATA%\ConnMgr\config\connections.json` |

Readable JSON. Only passwords, keys and passphrases are encrypted. Entries form a tree of folders, connections and credentials (format 2; files in the old format 1 are migrated automatically when opened):

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

## Usage

- **Tree** (left):
  - **Double-click a connection to connect**; a single click only selects it. If a tab for it is already open, ConnMgr switches to it ("Open another session" in the context menu opens an additional one).
  - **Right-click** opens the context menu with Properties, Duplicate, Export and Delete.
  - Clicking a folder or credential only selects it. The **properties tab** opens only via "📝 Properties" (or when creating an entry) and can be closed with ✖.
  - Double-click a folder to expand/collapse it.
  - Move entries by **drag & drop**: onto a folder = into it, onto an entry = before it, onto empty space = top level.
- **⚡ Quick connect** (field in the toolbar, `⌘K` / `Ctrl+K`): type an address and press Enter, e.g. `rdp://server`, `ssh://admin@host:2222`, `vnc://host:5901`, `horizon://view.example.com`, `admin@host`, `host:3389`, `[::1]:22`.
  - Without a scheme, the port decides: 3389 = RDP, 5900–5999 = VNC, anything else SSH.
  - The tab asks for the password (for RDP also the user).
  - **💾** in the tab saves the connection to the tree (into the selected folder).
  - **▾** shows the last ten addresses (never passwords).
- **📌 Pin / auto-hide:** When unpinned, only a narrow strip (») remains. Hovering over it slides the tree in over the content, and it disappears again when the mouse leaves, so the session keeps its size. The setting is saved.
- **Delete** asks for confirmation in a dialog; **Del** (Mac: ⌘⌫) deletes the selected entry.
- The status bar at the bottom shows the state of the most recently started connection and clears when it ends.
- **Credentials** are separate entries with a user, a password and optionally a **private SSH key with passphrase**. The key can be loaded from a file or pasted; ConnMgr shows its fingerprint and offers "Copy public key".
  - A connection uses *its own* credentials or a *specific* stored credential.
  - It can also *inherit* credentials from the nearest parent folder that has them.
- **Icons & colors** per entry, **favorites** (⭐) with a filter, **search** across name, host and user.
- **Duplicate** copies entries and whole folders; references to credentials copied along with them then point to the copies.
- **Menu ☰:**
  - *Change master password*: new salt, all secrets re-encrypted.
  - *Export everything* and *Import*. Single entries or folders are exported via the context menu.
  - Exports are separate files protected by **their own password**, which makes them easy to share.
  - Imports land in a new folder "Import …".
- `⌘S` / `Ctrl+S` saves the open entry.
- **⚙ Settings** (menu ☰): language (system, Deutsch, English), appearance (system, light, dark) and **unlock with Touch ID**. Changes take effect immediately and are saved in the connection file, so the lock screen also appears in the chosen language and theme.

## Sessions in tabs

A double-click opens SSH, SFTP, RDP and VNC as a tab directly in ConnMgr. "External" or the context menu launches the operating system's program instead. Horizon always runs in the Horizon Client (see below).

### SSH terminal

Built-in terminal (`xterm-256color`, 256 colors/truecolor).
- **Copy and paste:** select with the mouse and press `⌘C` to copy; `⌘V` pastes. On Windows/Linux, `Ctrl+C` without a selection sends the interrupt signal.
- **Scrollback:** the mouse wheel scrolls through 5000 lines of history.
- **Size:** follows the window.

**Authentication** in this order:
1. private key from the credentials,
2. **SSH agent** (`SSH_AUTH_SOCK`; on Windows the OpenSSH agent and Pageant),
3. default keys `~/.ssh/id_ed25519`, `id_ecdsa`, `id_rsa`,
4. password, then keyboard-interactive.

If a **passphrase** or password is missing, or the stored one is rejected, ConnMgr asks in the tab. If the server accepts only keys, you get a clear message instead of a password prompt.

**Host keys** are checked against `~/.ssh/known_hosts` (the same file OpenSSH uses). ConnMgr shows unknown keys with their fingerprint for confirmation; **changed keys are always rejected**.

### SFTP browser

Opened by double-clicking an SFTP connection, or via "📂 SFTP" for SSH connections. It uses the same authentication as the terminal.
- **Navigation:** path bar, Home, Refresh. Double-click opens a folder or downloads a file.
- **Upload:** via the button or by **drag & drop from Finder/Explorer**. Transfers run in the background with progress.
- **File operations:** new folder, rename, delete (folders only when empty).

### RDP

Via [IronRDP](https://github.com/Devolutions/IronRDP): TLS with **NLA** (CredSSP/NTLM).
- **Display:** the desktop matches the tab size in physical pixels. On Retina displays, ConnMgr tells Windows the matching scaling, e.g. 200 %.
- **Mouse:** including the wheel.
- **Keyboard:** text is sent to the server as Unicode, so it works regardless of keyboard layout. Special keys and shortcuts are sent as scancodes. On macOS ⌘ becomes Ctrl, so ⌘C/⌘X/⌘V work as usual.
- **Resizing:** when the tab size changes (window, sidebar), the Windows desktop adapts after half a second of rest (Display Control channel).
- **Clipboard:** text in both directions. Text copied in Windows lands in the local clipboard, and text copied locally is ready to paste in Windows. Note: as with mstsc, the server sees everything you copy locally while the tab is connected.

Sign-in: user as `user`, `DOMAIN\user` or `user@domain`. If user or password is missing, the tab asks for it.

**Certificates:** RDP servers usually have self-signed certificates. If a certificate cannot be verified, ConnMgr shows its SHA-256 fingerprint for confirmation and remembers it in `rdp_certificates.json` (next to the connection file). **A changed certificate is rejected.** Delete its entry there if the server was intentionally given a new one.

Not yet supported: Kerberos, smart cards, sound, drive redirection, files/images in the clipboard, RD Gateway.

### VNC

- **Display:** the image is scaled to fit the window.
- **Input:** mouse (including the wheel) and keyboard are forwarded.
- **Clipboard:** `⌘V`/`Ctrl+V` types the clipboard text on the remote side, and text from the server's clipboard is taken over.
- **Encodings:** ZRLE, CopyRect, Raw.

Authentication: classic **VNC password** (from the credentials or by prompt). macOS Screen Sharing requires Apple authentication (ARD) by default, which is not supported. Either enable *"VNC viewers may control screen with password"* there or open it externally.

### Omnissa Horizon

Horizon desktops and apps run in the **Omnissa Horizon Client**, because Blast and PCoIP are proprietary and cannot be embedded. ConnMgr launches it via a `horizon-client://` link, following the [Omnissa documentation](https://docs.omnissa.com/HorizonClient-MacGuide-V2512/SyntaxforCreatingURIs):

- **Fields:**
  - Connection Server and port (default 443).
  - **Desktop/App**: leave empty to choose in the client.
  - **Display protocol** (default, Blast, PCoIP): applies only when a desktop/app is set.
- **User and domain** come from the credentials (inherited ones too). `DOMAIN\user` becomes user + `domainName`. The link does not understand a UPN (`user@example.com`), so only the user part is passed.
- **Password:** deliberately not passed via the link. The client asks for it, and ConnMgr puts it on the clipboard for 30 s.
- **Quick connect:** `horizon://view.example.com/Finance Desktop`.
- **Launch:** macOS `open` (after checking that the Horizon Client is installed), Windows URL handler, Linux `xdg-open`.

Ended sessions can be reconnected from the tab. **Right-click a tab** for: Reconnect, Close, Close others, Close all connections. **Locking disconnects all sessions.**

### Tests against real servers

Tests marked `#[ignore]` run against a real sshd. `HOME` must point to a test directory: keys go in `.ssh`, and `known_hosts` is created there. The passphrase test additionally needs `enc_key` with the passphrase `geheim123`.

```bash
CONNMGR_E2E_SSH_PORT=2222 HOME=/path/to/test-home cargo test e2e -- --ignored --test-threads=1
```

The VNC test (with its own minimal RFB server) and the RDP certificate test (with its own server up to and including TLS) always run with `cargo test`.

## Unlock with Touch ID (macOS)

Enable it in the settings. On the next start ConnMgr asks for your fingerprint; after locking manually, use the 👆 button. The master password always keeps working, and "Enter Password" in the Touch ID prompt leads there.

- The **login keychain** holds the connection file's key (not the master password). ConnMgr can read it without a prompt; other apps cannot.
- **Limitation:** keychain items where macOS itself enforces the fingerprint are reserved for apps with an Apple Developer ID (otherwise error -34018). ConnMgr enforces the prompt itself instead. Malware already running under your user account that forges ConnMgr's signature could therefore get the key without a fingerprint.
- When the master password changes, the stored key is updated too. If it no longer matches (e.g. the file was changed elsewhere), ConnMgr discards it and asks for the password.

## Encryption

- A 256-bit key is derived from the **master password** with **Argon2id** (random salt).
- Each secret (password, private key, passphrase) is encrypted separately with **AES-256-GCM** and its own random nonce. The associated data is the entry's ID plus the field, so ciphertexts cannot be swapped between entries or between fields.
- `verifier` is an encrypted known text used to check the master password when unlocking.
- The key is kept only in memory and zeroed on lock/exit. The file is written atomically and (on Unix) with `0600` permissions.

## External clients

Via "External" or the context menu, ConnMgr launches the operating system's clients:

| Type | macOS | Linux | Windows |
|------|-------|-------|---------|
| SSH  | `ssh` in Terminal.app | `ssh` in a terminal emulator | `ssh` (OpenSSH client) |
| SFTP | `sftp` in Terminal.app | `sftp` in a terminal emulator | `sftp` |
| RDP  | `.rdp` file → "Windows App" | `xfreerdp3`/`xfreerdp` (with password) | `mstsc` (password via `cmdkey`) |
| VNC  | Screen Sharing (`vnc://`) | `vncviewer` | `vncviewer` (TigerVNC) |

**SSH/SFTP:** ConnMgr passes the password via `SSH_ASKPASS` (OpenSSH ≥ 8.4).
- **How:** for each connection, the app issues a one-time token valid for 2 minutes and serves the password to ssh over a local-only socket (127.0.0.1).
- **Never written down:** the password never appears on the command line or in a file.
- **Other prompts** appear in the terminal as usual: confirming a host key, the key passphrase, re-entry after a wrong password.

Where the client cannot accept a password (VNC, RDP on macOS), ConnMgr copies it to the clipboard on connect and clears it there after 30 seconds.

Note for Windows/RDP: `cmdkey` stores the credentials permanently in the Windows Credential Manager.
