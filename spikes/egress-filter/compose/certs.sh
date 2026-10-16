#!/bin/sh
# Test CA and one leaf per upstream, for the spike's test network only.
set -eu
dir="$1"
mkdir -p "$dir"
cd "$dir"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
  -keyout ca.key -out ca.crt -subj "/CN=Vilicus E14 test CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" 2>/dev/null
leaf() {
  name="$1"; sans="$2"
  printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "$sans" > "$name.ext"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$name.key" -out "$name.csr" -subj "/CN=$name" 2>/dev/null
  openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days 3650 \
    -extfile "$name.ext" -out "$name.crt" 2>/dev/null
}
leaf allowed "DNS:allowed.test,DNS:allowed6.test,DNS:other.test,DNS:budget.test,DNS:rebind-a.test,DNS:rebind-b.test"
leaf forbidden "DNS:forbidden.test,DNS:dns.google,DNS:cloudflare-dns.com"
leaf internal "DNS:internal.test,DNS:push.lan"
