#!/usr/bin/env bash
# Generates the TEST-ONLY self-signed PKI for the local Keycloak fixture in Story 2.1.
#
# Produces (in this directory):
#   ca.pem / ca-key.pem             — local test CA (RSA 2048)
#   server.pem / server-key.pem     — Keycloak HTTPS server cert (CN=localhost, SAN localhost+127.0.0.1), signed by CA
#   client.pem / client-key.pem     — the test JVM's TRANSPORT client cert (CN=smpp-mtls-client), signed by CA.
#                                     Presented on every IdP TLS handshake (the fixture runs client-auth REQUIRED);
#                                     its OAuth-level cert-auth mapping (the former client-x509 client) was removed
#                                     with the slice's RFC 8705 arm — Story 3.4 T8, 2026-08-29.
#   truststore.p12                  — PKCS12 holding ONLY the CA cert; the test JVM's minimal trust anchor for the
#                                     Keycloak server cert (AD-13: trust store never falls back to JDK cacerts).
#   client-keystore.p12             — PKCS12 holding the client cert + key; the test JVM's transport client identity
#                                     (loaded into the SSLContext the validation slice presents on every call).
#   keycloak-truststore.pem         — CA PEM that Keycloak trusts for verifying the mTLS client cert (KC_TRUSTSTORE_PATHS).
#   smpp-reverse-server*.pem        — Story 3.3 [B]: the reverse's internet-leg TLS listener server cert (SAN localhost+127.0.0.1).
#   smpp-forward-client*.pem        — Story 3.3 [B]: the forward's per-instance Mode C client cert (CN=smpp-forward-instance).
#   smpp-truststore.p12             — Story 3.3 [B]: CA-only PKCS12 anchoring both SMPP-leg trust directions (forward→reverse
#                                     server-cert validation; reverse.mode-c REQUIRE of the forward's client cert).
#   foreign-ca*.pem, smpp-foreign-client*.pem — Story 3.3 review: a SECOND, DISJOINT self-signed CA and a client
#                                     cert chained to it (CN=smpp-foreign-client). The mode-c REQUIRE listener must refuse
#                                     this peer — AC4's "unanchored one" arm (presented but not chained to the anchor).
#
# IMPORTANT: every cert here is self-signed TEST material for a local Docker Keycloak — NOT a production secret.
# Regenerating changes the CA and invalidates any committed truststore; the committed artifacts + this script
# together document provenance. Re-run with `bash generate.sh` to regenerate from scratch.
set -euo pipefail

cd "$(dirname "$0")"
PASS="smpp-test"   # PKCS12 store password (test-only)

rm -f ca.pem ca-key.pem ca.srl server.pem server-key.pem client.pem client-key.pem \
      truststore.p12 client-keystore.p12 keycloak-truststore.pem \
      foreign-ca.pem foreign-ca-key.pem smpp-foreign-client.pem smpp-foreign-client-key.pem .srl

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

# --- 3. Test-JVM transport client cert -----------------------------------------
# CN=smpp-mtls-client: the transport identity the test JVM presents on every IdP handshake (the fixture's
# KC_HTTPS_CLIENT_AUTH=required demands it). Its OAuth-level client-auth mapping died with the slice's RFC
# 8705 arm (Story 3.4 T8, 2026-08-29); the CN-only subject shape is kept as-generated.
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

# --- 7. SMPP internet-leg server cert (Story 3.3, [B] topology) ---------------
# The REVERSE proxy's internet-leg TLS listener presents this cert (CN=localhost,
# SAN localhost+127.0.0.1); the forward's TLS client validates it against smpp-truststore.p12.
# Signed by the SAME test CA (sections 1) — one PKI, two purposes (test-only).
openssl req -newkey rsa:2048 -nodes \
  -keyout smpp-reverse-server-key.pem -out smpp-reverse-server.csr \
  -subj "/CN=localhost/O=smpp-companions-test" 2>/dev/null
openssl x509 -req -in smpp-reverse-server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out smpp-reverse-server.pem -days 825 -sha256 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE") 2>/dev/null

# --- 8. SMPP per-instance forward client cert (Mode C mTLS) --------------------
# The FORWARD proxy's per-instance client cert (FR-AUTH-3: one cert per runtime instance),
# presented on the per-session internet-leg dial; a reverse.mode-c listener REQUIREs it.
openssl req -newkey rsa:2048 -nodes \
  -keyout smpp-forward-client-key.pem -out smpp-forward-client.csr \
  -subj "/CN=smpp-forward-instance/O=smpp-companions-test" 2>/dev/null
openssl x509 -req -in smpp-forward-client.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out smpp-forward-client.pem -days 825 -sha256 \
  -extfile <(printf "extendedKeyUsage=clientAuth\nbasicConstraints=critical,CA:FALSE") 2>/dev/null

# --- 9. SMPP-leg trust store (CA only) — AD-13 minimal anchor for BOTH directions
# One CA-only PKCS12 serves both internet-leg trust directions in the test PKI: the forward's
# client context (validating the reverse's server cert) and the reverse.mode-c REQUIRE listener
# (validating the forward's client cert). Minimal single-purpose store — never JDK cacerts.
keytool -importcert -noprompt -storetype PKCS12 -storepass "$PASS" \
  -keystore smpp-truststore.p12 -alias smpp-test-ca -file ca.pem 2>/dev/null

# --- 10. FOREIGN CA + unanchored client cert (Story 3.3 review, AC4 negative arm) ----
# A second, DISJOINT self-signed CA and a client cert chained to it. The mode-c REQUIRE listener
# must refuse this peer: the cert IS presented but is NOT chained to smpp-truststore.p12's anchor
# (openssl verify: OK under foreign-ca.pem, "error 20" under ca.pem) — the "unanchored one" arm.
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout foreign-ca-key.pem -out foreign-ca.pem -days 3650 \
  -subj "/CN=smpp-foreign-test-ca" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
openssl req -newkey rsa:2048 -nodes \
  -keyout smpp-foreign-client-key.pem -out smpp-foreign-client.csr \
  -subj "/CN=smpp-foreign-client/O=smpp-companions-test" 2>/dev/null
openssl x509 -req -in smpp-foreign-client.csr -CA foreign-ca.pem -CAkey foreign-ca-key.pem -CAcreateserial -out smpp-foreign-client.pem -days 825 -sha256 \
  -extfile <(printf "extendedKeyUsage=clientAuth\nbasicConstraints=critical,CA:FALSE") 2>/dev/null

# tidy CSR/serial intermediates
rm -f server.csr client.csr smpp-reverse-server.csr smpp-forward-client.csr smpp-foreign-client.csr ca.srl .srl foreign-ca.srl

echo "Generated test PKI:"
ls -1 ca.pem ca-key.pem server.pem server-key.pem client.pem client-key.pem \
      truststore.p12 client-keystore.p12 keycloak-truststore.pem \
      smpp-reverse-server.pem smpp-reverse-server-key.pem \
      smpp-forward-client.pem smpp-forward-client-key.pem smpp-truststore.p12 \
      foreign-ca.pem foreign-ca-key.pem smpp-foreign-client.pem smpp-foreign-client-key.pem
echo "Client cert subject DN (the test JVM's transport identity):"
openssl x509 -in client.pem -noout -subject
