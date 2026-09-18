#!/bin/zsh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE_DIR="$ROOT/.build/vendor-src"
OUTPUT_DIR="$ROOT/Vendor/bin/arm64"
ARCHIVE_DIR="$ROOT/Vendor/sources"
OPENVPN_TAG="v2.6.21"
AWG_GO_TAG="v3.1.20260828"
# 3.x: v1.0 does not know the AmneziaWG 3 interface keys and rejects such profiles.
AWG_TOOLS_TAG="v3.1.20260812"
XRAY_TAG="v26.9.9"

for tool in git go make autoreconf automake pkg-config brew; do
    command -v "$tool" >/dev/null || {
        print -u2 "Не найден $tool. Установите зависимости: brew install go automake pkg-config openssl@3 lzo lz4"
        exit 1
    }
done

mkdir -p "$SOURCE_DIR" "$OUTPUT_DIR" "$ARCHIVE_DIR"

checkout() {
    local url="$1" tag="$2" destination="$3"
    if [[ ! -d "$destination/.git" ]]; then
        git clone --filter=blob:none "$url" "$destination"
    fi
    git -C "$destination" fetch --tags --force
    git -C "$destination" switch --detach "$tag"
}

checkout https://github.com/amnezia-vpn/amneziawg-go.git "$AWG_GO_TAG" "$SOURCE_DIR/amneziawg-go"
(
    cd "$SOURCE_DIR/amneziawg-go"
    CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -o "$OUTPUT_DIR/amneziawg-go" .
    # One archive per tool: build-app.sh ships every archive here, and one left
    # from an older tag would be source that no longer matches the binary.
    rm -f -- "$ARCHIVE_DIR"/amneziawg-go-*.tar.gz(N)
    git archive --format=tar.gz --output="$ARCHIVE_DIR/amneziawg-go-$AWG_GO_TAG.tar.gz" "$AWG_GO_TAG"
)

checkout https://github.com/amnezia-vpn/amneziawg-tools.git "$AWG_TOOLS_TAG" "$SOURCE_DIR/amneziawg-tools"
(
    cd "$SOURCE_DIR/amneziawg-tools"
    make -C src clean
    make -C src wg PLATFORM=darwin
    cp src/wg "$OUTPUT_DIR/awg"
    rm -f -- "$ARCHIVE_DIR"/amneziawg-tools-*.tar.gz(N)
    git archive --format=tar.gz --output="$ARCHIVE_DIR/amneziawg-tools-$AWG_TOOLS_TAG.tar.gz" "$AWG_TOOLS_TAG"
)

checkout https://github.com/XTLS/Xray-core.git "$XRAY_TAG" "$SOURCE_DIR/xray-core"
(
    cd "$SOURCE_DIR/xray-core"
    CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o "$OUTPUT_DIR/xray" ./main
    rm -f -- "$ARCHIVE_DIR"/xray-core-*.tar.gz(N)
    git archive --format=tar.gz --output="$ARCHIVE_DIR/xray-core-$XRAY_TAG.tar.gz" "$XRAY_TAG"
)

checkout https://github.com/OpenVPN/openvpn.git "$OPENVPN_TAG" "$SOURCE_DIR/openvpn"
(
    cd "$SOURCE_DIR/openvpn"
    autoreconf -vi
    OPENSSL_PREFIX="$(brew --prefix openssl@3)"
    LZO_PREFIX="$(brew --prefix lzo)"
    LZ4_PREFIX="$(brew --prefix lz4)"
    ./configure \
        --disable-debug --disable-dependency-tracking --disable-shared --enable-static --disable-pkcs11 \
        CPPFLAGS="-I$OPENSSL_PREFIX/include -I$LZO_PREFIX/include -I$LZ4_PREFIX/include" \
        LDFLAGS="-L$OPENSSL_PREFIX/lib -L$LZO_PREFIX/lib -L$LZ4_PREFIX/lib" \
        OPENSSL_CFLAGS="-I$OPENSSL_PREFIX/include" \
        OPENSSL_LIBS="$OPENSSL_PREFIX/lib/libssl.a $OPENSSL_PREFIX/lib/libcrypto.a" \
        LZO_CFLAGS="-I$LZO_PREFIX/include" LZO_LIBS="$LZO_PREFIX/lib/liblzo2.a" \
        LZ4_CFLAGS="-I$LZ4_PREFIX/include" LZ4_LIBS="$LZ4_PREFIX/lib/liblz4.a"
    make -C src/compat -j "$(sysctl -n hw.logicalcpu)"
    make -C src/openvpn -j "$(sysctl -n hw.logicalcpu)"
    cp src/openvpn/openvpn "$OUTPUT_DIR/openvpn"
    rm -f -- "$ARCHIVE_DIR"/openvpn-*.tar.gz(N)
    git archive --format=tar.gz --output="$ARCHIVE_DIR/openvpn-$OPENVPN_TAG.tar.gz" "$OPENVPN_TAG"
)

chmod 755 "$OUTPUT_DIR/openvpn" "$OUTPUT_DIR/amneziawg-go" "$OUTPUT_DIR/awg" "$OUTPUT_DIR/xray"
for binary in "$OUTPUT_DIR/openvpn" "$OUTPUT_DIR/amneziawg-go" "$OUTPUT_DIR/awg" "$OUTPUT_DIR/xray"; do
    file "$binary" | grep -q 'arm64' || { print -u2 "$binary собран не для arm64"; exit 1; }
    if otool -L "$binary" | grep -q '/opt/homebrew'; then
        print -u2 "$binary содержит незапакованную Homebrew dylib"
        exit 1
    fi
done

(
    cd "$ROOT/Vendor"
    shasum -a 256 bin/arm64/openvpn bin/arm64/amneziawg-go bin/arm64/awg bin/arm64/xray sources/*.tar.gz > SHA256SUMS
)
print "VPN tools готовы в $OUTPUT_DIR"
