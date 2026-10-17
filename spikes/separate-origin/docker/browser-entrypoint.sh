#!/bin/sh
# Prepares a browser container: the test network's DNS server as the only resolver, and every
# test CA of the PKI as a trust anchor for Chromium (the user NSS database) and for Firefox (the
# persistent profile the harness opens). Then waits for `docker compose exec`.
set -eu
dns="$(awk '$1 == "server" && $2 == "dns" { print $3 }' /layout/instances.txt)"
printf 'nameserver %s\noptions timeout:2 attempts:2\n' "$dns" > /etc/resolv.conf
for db in "$HOME/.pki/nssdb" /profiles/firefox; do
  mkdir -p "$db"
  certutil -d "sql:$db" -N --empty-password
  for ca in /pki/ca-*.crt; do
    certutil -d "sql:$db" -A -t "C,," -n "$(basename "$ca" .crt)" -i "$ca"
  done
done
mkdir -p /profiles/chromium
echo "event=ready role=browser"
exec sleep infinity
