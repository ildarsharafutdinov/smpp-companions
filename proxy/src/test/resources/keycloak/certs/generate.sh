#!/usr/bin/env bash
# Generates the TEST-ONLY self-signed PKI for the local Keycloak fixture in Story 2.1.
#
# Produces (in this directory):
#   ca.pem / ca-key.pem             — local test CA (RSA 2048)
#   server.pem / server-key.pem     — Keycloak HTTPS server cert (CN=localhost, SAN localhost+127.0.0.1), signed by CA
#   client.pem / client-key.pem     — mTLS client cert for Client B (CN=smpp-mtls-client), signed by CA.
#                                     Its subject DN "CN=smpp-mtls-client" is mapped to the smpp-client-mtls client
#                                     (Keycloak client-x509 authenticator, RFC 8705 tls_client_auth).
#   truststore.p12                  — PKCS12 holding ONLY the CA cert; the test JVM's minimal trust anchor for the
#                                     Keycloak server cert (AD-13: trust store never falls back to JDK cacerts).
#   client-keystore.p12             — PKCS12 holding the client cert + key; the test JVM's mTLS client identity
#                                     (loaded into the SSLContext by the validation slice, Task 2/AC2 path 3).
#   keycloak-truststore.pem         — CA PEM that Keycloak trusts for verifying the mTLS client cert (KC_TRUSTSTORE_PATHS).
#
# IMPORTANT: every cert here is self-signed TEST material for a local Docker Keycloak — NOT a production secret.
# Regenerating changes the CA and invalidates any committed truststore; the committed artifacts + this script
# together document provenance. Re-run with `bash generate.sh` to regenerate from scratch.
set -euo pipefail

cd "$(dirname "$0")"
PASS="smpp-test"   # PKCS12 store password (test-only)

rm -f ca.pem ca-key.pem ca.srl server.pem server-key.pem client.pem client-key.pem \
      truststore.p12 client-keystore.p12 keycloak-truststore.pem .srl

# --- 1. Local test CA (CN-only subject so Keycloak's X.509 client authenticator
#         reads its DN unambiguously as "CN=smpp-test-ca" — no RDN reordering) ------
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout ca-key.pem -out ca.pem -days 3650 \
  -subj "/CN=smpp-test-ca" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

# --- 2. Keycloak HTTPS server cert ---------------------------------------------
openssl req -newkey rsa:2048 -nodes \
  -keyout server-key.pem -out server.csr \
  -subj "/CN=localhost/O=smpp-companions-test" 2>/dev/null
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out server.pem -days 825 -sha256 \
  -extfile <(printf "subjectAltName=DNS:localhost,DNS:keycloak,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE") 2>/dev/null

# --- 3. mTLS client cert (Client B / tls_client_auth) --------------------------
# CN=smpp-mtls-client is the subject DN mapped to the smpp-client-mtls Keycloak client.
# Kept CN-only deliberately so X500Principal.getName() == "CN=smpp-mtls-client" with zero RDN-format
# ambiguity for the client-x509 authenticator's subject-DN match (retro discovery #4).
openssl req -newkey rsa:2048 -nodes \
  -keyout client-key.pem -out client.csr \
  -subj "/CN=smpp-mtls-client" 2>/dev/null
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out client.pem -days 825 -sha256 \
  -extfile <(printf "extendedKeyUsage=clientAuth\nbasicConstraints=critical,CA:FALSE") 2>/dev/null

# --- 4. Test-JVM truststore (CA only) — AD-13 minimal trust anchor -------------
keytool -importcert -noprompt -storetype PKCS12 -storepass "$PASS" \
  -keystore truststore.p12 -alias smpp-test-ca -file ca.pem 2>/dev/null

# --- 5. Test-JVM mTLS client keystore (client cert + key) ----------------------
openssl pkcs12 -export -inkey client-key.pem -in client.pem -out client-keystore.p12 \
  -name smpp-mtls-client -passout pass:"$PASS" 2>/dev/null

# --- 6. Keycloak truststore (CA PEM) — verifies mTLS client certs -------------
cp ca.pem keycloak-truststore.pem

# tidy CSR/serial intermediates
rm -f server.csr client.csr ca.srl .srl

echo "Generated test PKI:"
ls -1 ca.pem ca-key.pem server.pem server-key.pem client.pem client-key.pem \
      truststore.p12 client-keystore.p12 keycloak-truststore.pem
echo "Client cert subject DN (mapped to smpp-client-mtls):"
openssl x509 -in client.pem -noout -subject
