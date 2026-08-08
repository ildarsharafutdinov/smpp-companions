#!/usr/bin/env bash
# Story 2.1 (Task 0 verification, retro discovery #4: verify against the REAL fixture, not assumptions).
# Probes the running Keycloak fixture across all four AD-12 paths the validation slice (Task 2) must express.
# Run AFTER `docker compose up -d --wait`, from anywhere — paths are absolute relative to this script.
#
# Exits non-zero only on a HARD infrastructure failure (realm not loaded / endpoints unreachable).
# Per-path outcomes are printed and captured for the Dev Agent Record; a path 3 (mTLS) failure is NOT a
# script failure here — it is the AC2/AC8 contract-revision signal (recorded, not silently degraded).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS="$HERE/certs"
BASE="https://localhost:8443/realms/smpp-companions"
CACERT="$CERTS/ca.pem"
REALM="smpp-companions"

# Per AD-12/AD-29 the proxy presents its per-instance mTLS client cert on EVERY IdP call, so this fixture
# runs KC_HTTPS_CLIENT_AUTH=require and every curl presents certs/client.pem for transport. OAuth-level auth
# still differs per client: Client A = client_secret (transport cert ignored by client-secret authenticator);
# Client B = the matched cert subject (client-x509 / RFC 8705 tls_client_auth).
c() { curl -sS --cacert "$CACERT" --cert "$CERTS/client.pem" --key "$CERTS/client-key.pem" "$@"; }
code() { curl -sS --cacert "$CACERT" --cert "$CERTS/client.pem" --key "$CERTS/client-key.pem" -o /dev/null -w "%{http_code}" "$@"; }

echo "=== fixture: $BASE ==="
echo

# ---- discovery: realm loaded + endpoints present -------------------------------------------
DISC="$(c "$BASE/.well-known/openid-configuration")"
TOKEN_EP="$(printf '%s' "$DISC" | jq -er '.token_endpoint // empty' 2>/dev/null || true)"
INTRO_EP="$(printf '%s' "$DISC" | jq -er '.introspection_endpoint // empty' 2>/dev/null || true)"
JWKS_EP="$(printf '%s' "$DISC" | jq -er '.jwks_uri // empty' 2>/dev/null || true)"
ISSUER="$(printf '%s' "$DISC" | jq -er '.issuer // empty' 2>/dev/null || true)"
if [[ -z "$TOKEN_EP" || -z "$JWKS_EP" ]]; then
  echo "HARD FAIL: realm '$REALM' not loaded or discovery incomplete."
  echo "  issuer=$ISSUER  token=$TOKEN_EP  jwks=$JWKS_EP"
  exit 1
fi
echo "discovery: issuer=$ISSUER"
echo "  token_endpoint      = $TOKEN_EP"
echo "  introspection_ep    = ${INTRO_EP:-<absent>}"
echo "  jwks_uri            = $JWKS_EP"
echo "  grant_types_supported = $(printf '%s' "$DISC" | jq -c '.grant_types_supported // []')"
echo

# ---- PATH 1: ROPC JWT happy path (Client A confidential + DAG) -----------------------------
ROPC_BODY="grant_type=password&client_id=smpp-client-confidential&client_secret=smpp-confidential-secret&username=testuser&password=testpass"
P1="$(c -X POST "$TOKEN_EP" -d "$ROPC_BODY")"
P1_AT="$(printf '%s' "$P1" | jq -r '.access_token // empty' 2>/dev/null || true)"
P1_HDR="$(printf '%s' "$P1_AT" | cut -d. -f1 | tr '_-' '/+' 2>/dev/null)"
P1_HDR="${P1_HDR}=="
P1_ALG="$(printf '%s' "$P1_HDR" | base64 -d 2>/dev/null | jq -r '.alg // empty' 2>/dev/null || true)"
P1_KID="$(printf '%s' "$P1_HDR" | base64 -d 2>/dev/null | jq -r '.kid // empty' 2>/dev/null || true)"
P1_TYP="$(printf '%s' "$P1_HDR" | base64 -d 2>/dev/null | jq -r '.typ // empty' 2>/dev/null || true)"
echo "PATH 1 (ROPC JWT, Client A): $([[ -n "$P1_AT" ]] && echo PASS || echo FAIL) — access_token=$( [[ -n "$P1_AT" ]] && echo 'JWT(' || echo '(none)')alg=$P1_ALG kid=$P1_KID typ=$P1_TYP token_len=${#P1_AT}"
echo

# ---- JWKS endpoint (defense-in-depth verify target) ----------------------------------------
JWKS="$(c "$JWKS_EP")"
NKEYS="$(printf '%s' "$JWKS" | jq -r '.keys | length' 2>/dev/null || echo 0)"
KID_PRESENT="no"
[[ -n "$P1_KID" ]] && printf '%s' "$JWKS" | jq -e --arg k "$P1_KID" '.keys[] | select(.kid==$k)' >/dev/null 2>&1 && KID_PRESENT="yes"
echo "JWKS: keys=$NKEYS  ROPC-token kid present in JWKS = $KID_PRESENT (kid-miss path needs a crafted/foreign kid)"
echo

# ---- PATH 2: RFC 7662 introspection (Client A) — active:true -------------------------------
if [[ -n "$INTRO_EP" && -n "$P1_AT" ]]; then
  P2="$(c -X POST "$INTRO_EP" -u "smpp-client-confidential:smpp-confidential-secret" -d "token=$P1_AT")"
  P2_ACTIVE="$(printf '%s' "$P2" | jq -r '.active // empty' 2>/dev/null || echo "?")"
  echo "PATH 2 (introspection): $( [[ "$P2_ACTIVE" == "true" ]] && echo PASS || echo FAIL) — active=$P2_ACTIVE"
else
  echo "PATH 2 (introspection): SKIPPED (no introspection endpoint or no token)"
fi
echo

# ---- PATH 4: DENY branches (401 invalid creds; AD-11) --------------------------------------
P4A="$(code -X POST "$TOKEN_EP" -d "grant_type=password&client_id=smpp-client-confidential&client_secret=smpp-confidential-secret&username=testuser&password=WRONGPASS")"
P4ERR="$(c -X POST "$TOKEN_EP" -d "grant_type=password&client_id=smpp-client-confidential&client_secret=smpp-confidential-secret&username=testuser&password=WRONGPASS" | jq -r '.error // empty' 2>/dev/null || true)"
echo "PATH 4a (DENY invalid user creds): http=$P4A error=$P4ERR"
echo "  FINDING (retro #4): Keycloak ROPC returns 400 invalid_grant for bad USER creds, 401 invalid_client for bad CLIENT"
echo "  secret. AC2 path4's 'invalid creds → 401 → DenyInvalid' is refined by this fixture: the slice (Task 2) must map"
echo "  BOTH 400-invalid_grant and 401-invalid_client → DenyInvalid (AD-11 '4xx≠200 → DENY' already covers both)."
P4B="$(code -X POST "$TOKEN_EP" -d "grant_type=password&client_id=smpp-client-confidential&client_secret=WRONG-SECRET&username=testuser&password=testpass")"
echo "PATH 4b (DENY bad client secret): http=$P4B (expect 401 → DenyInvalid)"
echo

# ---- PATH 3: RFC 8705 mTLS provider auth (Client B, client-x509, NO client_secret) ----------
# MOST LIKELY TO FAIL (AD-12 risk). 200+JWT ⇒ fixture supports ROPC+mTLS ⇒ port shape ratifiable.
# Non-200 ⇒ recorded finding feeding the AC8 contract-revision decision (Task 2/AC2 path 3).
P3="$(c -o /tmp/kc-p3.body -w "%{http_code}" \
       -X POST "$TOKEN_EP" -d "grant_type=password&client_id=smpp-client-mtls&username=testuser&password=testpass")"
P3BODY="$(cat /tmp/kc-p3.body 2>/dev/null)"
P3AT="$(printf '%s' "$P3BODY" | jq -r '.access_token // empty' 2>/dev/null || true)"
echo "PATH 3 (ROPC + mTLS, Client B, no client_secret): http=$P3"
if [[ "$P3" == "200" && -n "$P3AT" ]]; then
  echo "  ⇒ PASS — fixture supports ROPC+mTLS (RFC 8705 tls_client_auth); port shape can express path 3."
elif [[ "$P3" == "401" ]]; then
  echo "  ⇒ CERT MATCHED BUT REJECTED — $(printf '%s' "$P3BODY" | jq -c '{error,error_description}' 2>/dev/null || echo "$P3BODY")"
else
  echo "  ⇒ NOT-200 — $(printf '%s' "$P3BODY" | jq -c '{error,error_description}' 2>/dev/null | head -c 400 || true)"
  echo "  (verify: Keycloak logged the client cert? subject DN 'CN=smpp-mtls-client' matched client attribute x509cert?)"
fi
echo
echo "=== fixture verification complete ==="
