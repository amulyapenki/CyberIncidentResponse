#!/bin/sh
# Creates a self-signed TLS certificate for WINDX. Run once per deployment.
# Hand the printed fingerprint to responders (on paper) so they can verify they
# are talking to the real WINDX and not an attacker in the middle.
set -e
DIR="${LIFEBOAT_DATA:-$(dirname "$0")/../data}/tls"
HOSTNAME_CN="${1:-windx.local}"
mkdir -p "$DIR"
chmod 700 "$DIR"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 \
  -keyout "$DIR/key.pem" -out "$DIR/cert.pem" -subj "/CN=$HOSTNAME_CN/O=WINDX" \
  -addext "subjectAltName=DNS:$HOSTNAME_CN,DNS:localhost,IP:127.0.0.1" 2>/dev/null
chmod 600 "$DIR/key.pem"
echo "Certificate written to $DIR"
echo "SHA-256 fingerprint (print this and give it to your team):"
openssl x509 -in "$DIR/cert.pem" -noout -fingerprint -sha256 | cut -d= -f2
