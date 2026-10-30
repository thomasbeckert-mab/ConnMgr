#!/bin/sh
# Baut ConMgr.app. Als eigene App fragt macOS beim ersten Verbinden nach der
# Berechtigung „Lokales Netzwerk“ – aus fremden Terminals gestartet gilt sonst
# deren Berechtigung (und Verbindungen ins LAN scheitern mit „No route to host“).
set -eu
cd "$(dirname "$0")/.."

cargo build --release

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
APP=target/release/bundle/ConMgr.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp target/release/conmgr "$APP/Contents/MacOS/conmgr"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>ConMgr</string>
    <key>CFBundleDisplayName</key><string>ConMgr</string>
    <key>CFBundleIdentifier</key><string>app.conmgr.ConMgr</string>
    <key>CFBundleExecutable</key><string>conmgr</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleVersion</key><string>$VERSION</string>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>LSMinimumSystemVersion</key><string>11.0</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSLocalNetworkUsageDescription</key>
    <string>ConMgr verbindet sich per SSH, RDP und VNC mit Rechnern in deinem Netzwerk.</string>
</dict>
</plist>
PLIST

# Mit dem lokalen Zertifikat bleibt die Signatur-Anforderung über Neubauten gleich,
# und macOS behält die Freigabe „Lokales Netzwerk“. Ad-hoc ändert sie bei jedem Bau.
IDENTITY="ConMgr Local Signing"
if security find-identity -p codesigning 2>/dev/null | grep -q "\"$IDENTITY\""; then
    codesign --force --sign "$IDENTITY" "$APP"
else
    codesign --force --sign - "$APP"
    echo "Hinweis: ad-hoc signiert – nach jedem Neubau muss die Freigabe „Lokales Netzwerk“"
    echo "neu gesetzt werden. Abhilfe: ./scripts/create-signing-cert-macos.sh"
fi
echo "Fertig: $APP"
