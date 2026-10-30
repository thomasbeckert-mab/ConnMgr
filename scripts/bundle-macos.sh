#!/bin/sh
# Baut ConnMgr.app. Als eigene App fragt macOS beim ersten Verbinden nach der
# Berechtigung „Lokales Netzwerk“ – aus fremden Terminals gestartet gilt sonst
# deren Berechtigung (und Verbindungen ins LAN scheitern mit „No route to host“).
set -eu
cd "$(dirname "$0")/.."

cargo build --release

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
APP=target/release/bundle/ConnMgr.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp target/release/connmgr "$APP/Contents/MacOS/connmgr"

# App-Icon aus assets/icon-macos.svg (randlos; macOS schneidet die Form selbst zu)
ICONSET=target/release/bundle/AppIcon.iconset
rm -rf "$ICONSET"
cargo run --quiet --release --example render_icon -- "$ICONSET"
iconutil -c icns -o "$APP/Contents/Resources/AppIcon.icns" "$ICONSET"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>ConnMgr</string>
    <key>CFBundleDisplayName</key><string>ConnMgr</string>
    <key>CFBundleIdentifier</key><string>app.conmgr.ConMgr</string>
    <!-- Kennung bleibt vom alten Namen ConMgr: an ihr hängt die Freigabe „Lokales Netzwerk“. -->
    <key>CFBundleExecutable</key><string>connmgr</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleVersion</key><string>$VERSION</string>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>LSMinimumSystemVersion</key><string>11.0</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSLocalNetworkUsageDescription</key>
    <string>ConnMgr connects to computers on your network via SSH, SFTP, RDP and VNC.</string>
    <key>CFBundleDevelopmentRegion</key><string>en</string>
    <key>CFBundleLocalizations</key><array><string>en</string><string>de</string></array>
</dict>
</plist>
PLIST

# Übersetzter Text für die macOS-Rückfrage „Lokales Netzwerk“.
mkdir -p "$APP/Contents/Resources/en.lproj" "$APP/Contents/Resources/de.lproj"
echo '"NSLocalNetworkUsageDescription" = "ConnMgr connects to computers on your network via SSH, SFTP, RDP and VNC.";' \
    > "$APP/Contents/Resources/en.lproj/InfoPlist.strings"
echo '"NSLocalNetworkUsageDescription" = "ConnMgr verbindet sich per SSH, SFTP, RDP und VNC mit Rechnern in deinem Netzwerk.";' \
    > "$APP/Contents/Resources/de.lproj/InfoPlist.strings"

# Mit dem lokalen Zertifikat bleibt die Signatur-Anforderung über Neubauten gleich,
# und macOS behält die Freigabe „Lokales Netzwerk“. Ad-hoc ändert sie bei jedem Bau.
# Name des Zertifikats im Schlüsselbund (vom alten App-Namen ConMgr, nicht sichtbar).
IDENTITY="ConMgr Local Signing"
if security find-identity -p codesigning 2>/dev/null | grep -q "\"$IDENTITY\""; then
    codesign --force --sign "$IDENTITY" "$APP"
else
    codesign --force --sign - "$APP"
    echo "Hinweis: ad-hoc signiert – nach jedem Neubau muss die Freigabe „Lokales Netzwerk“"
    echo "neu gesetzt werden. Abhilfe: ./scripts/create-signing-cert-macos.sh"
fi
# Finder und Dock zwischenspeichern Icons; geänderte Zeitstempel lassen sie neu lesen.
touch "$APP" "$APP/Contents/Info.plist"
echo "Fertig: $APP"
