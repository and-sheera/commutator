#!/bin/zsh
set -euo pipefail

IDENTITY="Commutator Local Development"
KEYCHAIN="$HOME/Library/Keychains/login.keychain-db"

if /usr/bin/security find-identity -v -p codesigning "$KEYCHAIN" | /usr/bin/grep -Fq "\"$IDENTITY\""; then
    print "Локальная подпись уже установлена: $IDENTITY"
    exit 0
fi

TEMP_DIR="$(/usr/bin/mktemp -d)"
trap '/bin/rm -rf -- "$TEMP_DIR"' EXIT
P12_PASSWORD="$(/usr/bin/uuidgen)"

/opt/homebrew/bin/openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 3650 \
    -subj "/CN=$IDENTITY/O=Commutator Local Development" \
    -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=critical,codeSigning" \
    -keyout "$TEMP_DIR/key.pem" -out "$TEMP_DIR/cert.pem"
/opt/homebrew/bin/openssl pkcs12 -export -passout "pass:$P12_PASSWORD" \
    -inkey "$TEMP_DIR/key.pem" -in "$TEMP_DIR/cert.pem" -out "$TEMP_DIR/identity.p12"

/usr/bin/security import "$TEMP_DIR/identity.p12" -k "$KEYCHAIN" -f pkcs12 -P "$P12_PASSWORD" -x -T /usr/bin/codesign
/usr/bin/security add-trusted-cert -r trustRoot -p codeSign -k "$KEYCHAIN" "$TEMP_DIR/cert.pem"

/usr/bin/security find-identity -v -p codesigning "$KEYCHAIN" | /usr/bin/grep -F "\"$IDENTITY\""
print "Готово. Следующие сборки будут иметь постоянную подпись и не будут повторно запрашивать доступ к Keychain."
