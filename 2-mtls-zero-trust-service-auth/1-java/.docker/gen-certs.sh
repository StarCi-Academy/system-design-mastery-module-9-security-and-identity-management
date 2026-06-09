#!/bin/sh
# gen-certs.sh — internal CA + short-lived server/client certs for the mTLS lab.
# Runs once in an alpine+openssl init container; output lands in the shared /certs volume.
# All certs share ONE internal CA so each side can verify the other (mutual trust).
set -e

CERTS_DIR="${CERTS_DIR:-/certs}"
DAYS="${CERT_DAYS:-1}"   # Short-lived on purpose — zero-trust certs rotate fast.

# Idempotent: skip if the bundle already exists (compose may re-run the init container).
if [ -f "${CERTS_DIR}/ca.crt" ] && [ -f "${CERTS_DIR}/server.crt" ] && [ -f "${CERTS_DIR}/client.crt" ]; then
  echo "[cert-init] Certificates already present in ${CERTS_DIR}, skipping generation."
  exit 0
fi

mkdir -p "${CERTS_DIR}"
cd "${CERTS_DIR}"

echo "[cert-init] 1/3 Creating the internal Certificate Authority (CA)..."
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -subj "/O=StarCi-Internal/CN=StarCi Internal Root CA" -out ca.crt

echo "[cert-init] 2/3 Issuing the SERVER certificate for service-b (CN=service-b)..."
openssl genrsa -out server.key 2048
openssl req -new -key server.key -subj "/O=StarCi-Internal/CN=service-b" -out server.csr
# SAN must list the service DNS name so TLS hostname verification passes.
printf "subjectAltName=DNS:service-b,DNS:localhost\nextendedKeyUsage=serverAuth\n" > server.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days "${DAYS}" -sha256 -extfile server.ext -out server.crt

echo "[cert-init] 3/3 Issuing the CLIENT certificate for service-a (CN=service-a)..."
openssl genrsa -out client.key 2048
openssl req -new -key client.key -subj "/O=StarCi-Internal/CN=service-a" -out client.csr
printf "extendedKeyUsage=clientAuth\n" > client.ext
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days "${DAYS}" -sha256 -extfile client.ext -out client.crt

# Java consumes PKCS12 keystores (identity) + a truststore (the CA), not raw PEM.
STOREPASS="${STOREPASS:-changeit}"
echo "[cert-init] Java: building PKCS12 keystores + CA truststore..."
# Server identity keystore (service-b).
openssl pkcs12 -export -inkey server.key -in server.crt -name service-b \
  -passout "pass:${STOREPASS}" -out server.p12
# Client identity keystore (service-a).
openssl pkcs12 -export -inkey client.key -in client.crt -name service-a \
  -passout "pass:${STOREPASS}" -out client.p12
# Truststore = CA only, built with keytool so Java's PKIXParameters can load it.
# OpenSSL PKCS12 -nokeys produces a bag that Java treats as empty trust anchors.
keytool -importcert -alias ca -file ca.crt \
  -keystore truststore.p12 -storetype PKCS12 \
  -storepass "${STOREPASS}" -noprompt

# World-readable so the unprivileged app containers can mount + read the bundle.
chmod 644 *.crt *.key *.p12
echo "[cert-init] Done. Issued ca.crt, server/client PEM + server.p12/client.p12/truststore.p12."
