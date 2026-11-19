#!/bin/sh
# Initialize the SoftHSM2 token on first start, then serve it with p11-kit server.
#
#   SIGNER_TOKEN_LABEL  token label (default jip)
#   SIGNER_PIN / SIGNER_PIN_FILE   user PIN set at initialization (required on first start)
#
# The key itself is created by the Fuseki module on first use (PROVENANCE_PKCS11_GENERATE),
# through the socket, so it is generated inside the token and never exported.
set -eu

STATE=/var/lib/jip-signer
SOCKET=/run/jip-signer/pkcs11.sock
LABEL="${SIGNER_TOKEN_LABEL:-jip}"
export SOFTHSM2_CONF="$STATE/softhsm2.conf"

mkdir -p "$STATE/tokens"
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = INFO\n' "$STATE" > "$SOFTHSM2_CONF"

# PKCS#11 labels are padded with spaces to 32 characters.
if ! softhsm2-util --show-slots | grep -qE "Label: *$LABEL *\$"; then
  PIN="${SIGNER_PIN:-}"
  [ -n "${SIGNER_PIN_FILE:-}" ] && PIN="$(cat "$SIGNER_PIN_FILE")"
  [ -n "$PIN" ] || { echo "jip-signer: SIGNER_PIN or SIGNER_PIN_FILE is needed to initialize the token" >&2; exit 1; }
  # The security officer PIN is only needed to initialize or reset the token; it is not kept.
  SO_PIN="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  softhsm2-util --init-token --free --label "$LABEL" --pin "$PIN" --so-pin "$SO_PIN" >/dev/null
  echo "jip-signer: initialized token '$LABEL'"
fi

rm -f "$SOCKET"
echo "jip-signer: serving token '$LABEL' on $SOCKET"
exec p11-kit server -f --provider /usr/local/lib/libsofthsm2.so -n "$SOCKET" "pkcs11:token=$LABEL"
