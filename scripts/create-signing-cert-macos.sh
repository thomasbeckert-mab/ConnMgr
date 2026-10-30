#!/bin/sh
# Legt einmalig ein selbst signiertes Code-Signing-Zertifikat „ConMgr Local Signing“
# im Anmelde-Schlüsselbund an. bundle-macos.sh signiert damit; die Signatur-Anforderung
# hängt dann am Zertifikat statt am Inhalt, und macOS behält die Freigabe
# „Lokales Netzwerk“ über Neubauten hinweg. Nur codesign darf den Schlüssel nutzen.
set -eu

IDENTITY="ConMgr Local Signing"
if security find-identity -p codesigning 2>/dev/null | grep -q "\"$IDENTITY\""; then
    echo "„$IDENTITY“ ist bereits vorhanden."
    exit 0
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/cert.cnf" <<EOF
[req]
distinguished_name = dn
prompt = no
x509_extensions = ext
[dn]
CN = $IDENTITY
[ext]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,codeSigning
subjectKeyIdentifier = hash
EOF

# /usr/bin/openssl (LibreSSL) erzeugt PKCS#12, das `security import` sicher lesen kann.
/usr/bin/openssl req -x509 -newkey rsa:3072 -nodes -days 3650 \
    -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -config "$WORK/cert.cnf" 2>/dev/null
PASS=$(/usr/bin/openssl rand -hex 16)
/usr/bin/openssl pkcs12 -export -name "$IDENTITY" -inkey "$WORK/key.pem" -in "$WORK/cert.pem" \
    -out "$WORK/cert.p12" -passout "pass:$PASS"

security import "$WORK/cert.p12" -k "$HOME/Library/Keychains/login.keychain-db" -P "$PASS" -T /usr/bin/codesign
echo "„$IDENTITY“ angelegt (10 Jahre gültig). Jetzt ./scripts/bundle-macos.sh ausführen."
