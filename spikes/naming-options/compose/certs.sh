#!/usr/bin/env bash
# Issues the E24 test certificates into /pki (a compose volume). Two test authorities:
# - "stand-in public CA": plays the public CA that issues a DNS-01 certificate for a dynamic DNS
#   name, and the certificate of a private-network (overlay) name. Browsers get it as an added
#   root, because a real public root cannot be reproduced offline.
# - "local CA": the household's own authority, installed on each device.
# Plus one self-signed certificate, like the wizard's temporary certificate (FR-4).
set -euo pipefail
cd /pki
umask 022

new_ca() {
  local name="$1" subject="$2"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
    -subj "/CN=$subject" -keyout "$name.key" -out "$name.crt" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
}

# leaf NAME CA SAN: a 90-day server certificate signed by CA, chain written to NAME.crt.
leaf() {
  local name="$1" ca="$2" san="$3"
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "/CN=${name}" -keyout "$name.key" -out "$name.csr" 2>/dev/null
  printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\nbasicConstraints=critical,CA:FALSE\n' "$san" >"$name.ext"
  openssl x509 -req -in "$name.csr" -CA "$ca.crt" -CAkey "$ca.key" -CAcreateserial -days 90 \
    -extfile "$name.ext" -out "$name.leaf" 2>/dev/null
  cat "$name.leaf" "$ca.crt" >"$name.crt"
}

new_ca public-ca "E24 stand-in public CA"
new_ca local-ca "E24 local CA"
leaf dyndns public-ca "DNS:household.dyn.example"
leaf overlay public-ca "DNS:household.tailnet.example"
leaf localca local-ca "DNS:vilicus.home.arpa"
leaf mdns local-ca "DNS:vilicus.local"
leaf ip local-ca "IP:10.88.0.24"

# A name that is first served with a temporary self-signed certificate (port 8443) and then with
# its real certificate (port 443): the case where the temporary name equals the instance name.
leaf same local-ca "DNS:same.home.arpa"

# self_signed NAME SAN: a temporary certificate like the wizard's.
self_signed() {
  local name="$1" san="$2"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
    -subj "/CN=E24 temporary certificate" -keyout "$name.key" -out "$name.crt" \
    -addext "subjectAltName=$san" -addext "extendedKeyUsage=serverAuth" 2>/dev/null
}
# The host's private address, its LAN name, and localhost (the wizard through a port forward).
self_signed selfsigned "DNS:host01.home.arpa,DNS:localhost,IP:10.88.0.25"
self_signed selfsigned-same "DNS:same.home.arpa"

chmod 0644 ./*.key
openssl x509 -in selfsigned.crt -noout -fingerprint -sha256 | sed 's/^/INFO selfsigned /'
