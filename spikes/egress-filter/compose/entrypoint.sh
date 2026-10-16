#!/bin/sh
# Starts one service of the E14 test network; the role is the first argument.
set -eu
role="$1"
drop() {
  user="$1"
  shift
  setpriv --reuid="$user" --regid="$(id -g "$user")" --clear-groups "$@"
}
case "$role" in
  proxy)
    # The proxy resolves through the scripted resolver only, not Docker's embedded DNS.
    # The search list and ndots would turn a relative name into `<name>.corp.test` first; the
    # proxy resolves absolute names, so the resolver must never see that suffix.
    printf 'nameserver 203.0.113.53\nsearch corp.test\noptions timeout:2 attempts:2 ndots:5\n' > /etc/resolv.conf
    install -d -o egress -g egress -m 0755 /run/egress
    # Loopback canaries on the proxy host: a name resolving to 127.0.0.1, ::1 or 0.0.0.0 would
    # reach them if the address check let it through.
    drop nobody egress-probe canary --listen 127.0.0.1:8443 --name proxy-host-loopback &
    drop nobody egress-probe canary --listen '[::1]:8443' --name proxy-host-loopback &
    exec setpriv --reuid=egress --regid=egress --clear-groups \
      egress-proxy /etc/egress-test/proxy.conf /run/egress
    ;;
  resolver)
    exec egress-resolver /etc/egress-test/zone.txt '[::]:53'
    ;;
  allowed)
    head -c 67108864 /dev/urandom > /srv/big.bin
    sha256sum /srv/big.bin | cut -d ' ' -f 1 > /srv/big.sha256
    drop nobody python3 -I /etc/egress-test/ws_backend.py &
    exec nginx -c /etc/egress-test/nginx-allowed.conf -g 'daemon off;'
    ;;
  forbidden)
    exec nginx -c /etc/egress-test/nginx-forbidden.conf -g 'daemon off;'
    ;;
  internal)
    exec nginx -c /etc/egress-test/nginx-internal.conf -g 'daemon off;'
    ;;
  client)
    # The D115 forwarder shape: a loopback listener inside a namespace with no other network,
    # forwarding to the caller's own Unix socket; the proxy sees the forwarder's uid.
    drop plugin-a socat TCP-LISTEN:3128,bind=127.0.0.1,reuseaddr,fork UNIX-CONNECT:/run/egress/plugin-a.sock &
    drop plugin-b socat TCP-LISTEN:3129,bind=127.0.0.1,reuseaddr,fork UNIX-CONNECT:/run/egress/plugin-b.sock &
    # A relay through plugin-a's CONNECT tunnel to allowed.test:443, so a TLS client can send
    # any SNI over a tunnel whose CONNECT target is fixed.
    drop plugin-a socat TCP-LISTEN:4443,bind=127.0.0.1,reuseaddr,fork PROXY:127.0.0.1:allowed.test:443,proxyport=3128 &
    # The same through plugin-b, whose tunnels carry the SNI check.
    drop plugin-b socat TCP-LISTEN:4444,bind=127.0.0.1,reuseaddr,fork PROXY:127.0.0.1:other.test:443,proxyport=3129 &
    exec sleep infinity
    ;;
  sandbox)
    exec /lib/systemd/systemd
    ;;
  *)
    echo "unknown role $role" >&2
    exit 2
    ;;
esac
