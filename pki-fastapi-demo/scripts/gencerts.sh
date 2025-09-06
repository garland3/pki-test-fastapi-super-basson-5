#!/usr/bin/env bash
set -euo pipefail
CN="${1:-Test User}"
PWDIR="$(cd "$(dirname "$0")/.."; pwd)"
CDIR="$PWDIR/certs"
mkdir -p "$CDIR"

# CA
openssl genrsa -out "$CDIR/ca.key" 4096
openssl req -x509 -new -nodes -key "$CDIR/ca.key" -sha256 -days 3650 \
  -subj "/C=US/ST=NM/L=Albuquerque/O=Dev CA/CN=Local Dev Root CA" \
  -out "$CDIR/ca.crt"

# Server (for localhost)
cat >"$CDIR/server.ext"<<EOF
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF
openssl genrsa -out "$CDIR/server.key" 2048
openssl req -new -key "$CDIR/server.key" -subj "/CN=localhost" -out "$CDIR/server.csr"
openssl x509 -req -in "$CDIR/server.csr" -CA "$CDIR/ca.crt" -CAkey "$CDIR/ca.key" -CAcreateserial \
  -out "$CDIR/server.crt" -days 825 -sha256 -extfile "$CDIR/server.ext"

# Client
cat >"$CDIR/client.ext"<<EOF
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage=clientAuth
EOF
openssl genrsa -out "$CDIR/client.key" 2048
openssl req -new -key "$CDIR/client.key" -subj "/CN=${CN}" -out "$CDIR/client.csr"
openssl x509 -req -in "$CDIR/client.csr" -CA "$CDIR/ca.crt" -CAkey "$CDIR/ca.key" -CAcreateserial \
  -out "$CDIR/client.crt" -days 825 -sha256 -extfile "$CDIR/client.ext"

# PFX for Windows import (password: changeit)
openssl pkcs12 -export -inkey "$CDIR/client.key" -in "$CDIR/client.crt" -certfile "$CDIR/ca.crt" \
  -out "$CDIR/client.pfx" -password pass:changeit

echo "Done. Files in: $CDIR"
