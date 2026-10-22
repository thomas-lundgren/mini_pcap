#!/usr/bin/env bash
# Creates a TEST-ONLY CA and receiver certificates. The CA certificate (public) is
# copied into the debug build's trust anchors (app/src/debug/res/raw/test_ca.pem);
# release builds trust only system CAs. Private keys stay local (gitignored).
#   ./make_certs.sh <receiver-ip> [extra-ip...]
set -euo pipefail
cd "$(dirname "$0")/certs"
IP=${1:?receiver IP required}
shift || true
SAN="DNS:localhost,IP:127.0.0.1,IP:$IP"
for x in "$@"; do SAN="$SAN,IP:$x"; done
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 825 -subj "/CN=mini_pcap_collect TEST CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.pem
mk() { # name san
  openssl ecparam -name prime256v1 -genkey -noout -out "$1.key"
  openssl req -new -key "$1.key" -subj "/CN=$1" -out "$1.csr"
  openssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -days 397 -sha256 \
    -extfile <(printf "subjectAltName=%s\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE" "$2") -out "$1.pem"
  rm -f "$1.csr"
}
mk server "$SAN"
mk wronghost "DNS:wrong.invalid"           # valid chain, hostname mismatch (negative test)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout untrusted.key \
  -subj "/CN=untrusted" -addext "subjectAltName=$SAN" -days 30 -out untrusted.pem 2>/dev/null  # not signed by test CA
mkdir -p ../../../app/src/debug/res/raw
cp ca.pem ../../../app/src/debug/res/raw/test_ca.pem
echo "certs written; debug trust anchor updated (rebuild the debug APK)"
