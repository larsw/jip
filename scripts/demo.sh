#!/usr/bin/env bash
# End-to-end demo of jena-intrinsic-provenance against the Docker image.
#
#   scripts/demo.sh [--reset] [--tsa "<url> [<url>...]"] [--no-tsa]
#
#   --reset    delete the demo's Docker volumes first (databases, the signer's token and key)
#   --tsa      RFC 3161 timestamp authorities, in priority order (default: $TSA_DEFAULT,
#              or $JIP_TSA_URLS if set)
#   --no-tsa   issue attestations without timestamps
#
# Needs: docker (compose v2), curl, jq. Writes files to ./demo-out. JIP_PORT sets the host port
# (default 3030).
set -euo pipefail

TSA_DEFAULT="http://timestamp.digicert.com http://timestamp.sectigo.com https://freetsa.org/tsr"
TSA_URLS="${JIP_TSA_URLS-$TSA_DEFAULT}"
RESET=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --reset) RESET=1 ;;
    --tsa) [[ $# -ge 2 ]] || { echo "--tsa needs a value" >&2; exit 2; }; TSA_URLS="$2"; shift ;;
    --no-tsa) TSA_URLS="" ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done
# docker-compose.yml passes this to the server as PROVENANCE_TSA_URLS.
export JIP_TSA_URLS="$TSA_URLS"

cd "$(dirname "$0")/.."
BASE=http://localhost:${JIP_PORT:-3030}
IMAGE=jena-intrinsic-provenance:0.13.0
OUT="$PWD/demo-out"
mkdir -p "$OUT"

bold() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }
header() { grep -i "^$1:" "$2" | tr -d '\r' | awk '{print $2}'; }

wait_ready() {
  for _ in $(seq 1 60); do
    curl -fs "$BASE/\$/ping" >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "Fuseki did not start" >&2; docker compose logs --tail 50 fuseki >&2; exit 1
}

# query <sparql> <results-file> <headers-file>
query() {
  curl -fsS -D "$3" -o "$2" -H 'Accept: application/sparql-results+json' \
       --data-urlencode "query=$1" "$BASE/ds/sparql"
}

update() {
  curl -fsS -D "$OUT/update.headers" -o /dev/null -H 'Content-Type: application/sparql-update' \
       --data-binary "$1" "$BASE/ds/update"
  header X-Dataset-Version "$OUT/update.headers"
}

# verify <results> <attestation>  -> prints report, returns verifier exit status
verify() {
  docker run --rm -v "$OUT:/data:ro" "$IMAGE" verify \
    --results "/data/$1" --attestation "/data/$2" --expect-key "$DID" | sed 's/^/   | /'
  return "${PIPESTATUS[0]}"
}

# attestation <cert-iri> <file>: fetch it; while its RFC 3161 timestamp is still being fetched
# the server answers 202 Accepted with Retry-After, so wait and ask again.
fetch_attestation() {
  local url="$BASE/\$/provenance/attestation/${1#urn:uuid:}" code
  for _ in $(seq 1 60); do
    code=$(curl -sS -H 'Accept: text/turtle' -D "$OUT/attestation.headers" -o "$OUT/$2" -w '%{http_code}' "$url")
    case "$code" in
      200) return 0 ;;
      202) sleep "$(header Retry-After "$OUT/attestation.headers")" ;;
      *) echo "attestation $1: HTTP $code" >&2; return 1 ;;
    esac
  done
  echo "attestation $1: timestamp still pending after 60 tries" >&2; return 1
}

# show <file>: print an attestation, eliding the long base64 timestamp token
show() {
  sed -E 's/"([A-Za-z0-9+\/=]{48})[A-Za-z0-9+\/=]{16,}"/"\1..."/' "$1" | sed 's/^/   /'
}

PREFIXES='PREFIX ex: <http://example.org/>
PREFIX jip: <https://larsw.xyz/jip/>'
ATTESTED_QUERY="$PREFIXES
SELECT ?name ?email ?attestation WHERE {
  SERVICE <urn:x-provenance:attest> {
    SELECT ?name ?email WHERE { ?p ex:name ?name OPTIONAL { ?p ex:email ?email } } ORDER BY ?name
  }
}"

# ---------------------------------------------------------------------------
if [[ -n "$RESET" ]]; then
  bold "Reset: removing the demo volume"
  docker compose down -v
fi

bold "Build and start the signer (PKCS#11 token) and Fuseki 6.2.0 + module"
docker compose --progress quiet up -d --build
wait_ready
curl -fsS "$BASE/\$/provenance/key" -o "$OUT/key.json"
DID=$(jq -r .id "$OUT/key.json")
info "signing key: $DID"
info "signer: $(jq -r '"\(.signer), \(.keyType), \(.cryptosuite)"' "$OUT/key.json")"
if [[ "$(jq -r .signer "$OUT/key.json")" == pkcs11 ]]; then
  info "the key lives in the signer container (no network); Fuseki reaches it over a Unix socket:"
  docker compose ps --format '{{.Service}}: {{.Image}} ({{.Status}})' | sed 's/^/     /'
fi
V0=$(curl -fsS "$BASE/\$/provenance/version/ds" | jq -r .version)
info "persistent data version of /ds: $V0"
if [[ -n "$TSA_URLS" ]]; then
  info "timestamp authorities (priority order): $TSA_URLS"
else
  info "timestamp authorities: none (attestations are not timestamped)"
fi

bold "1. Load data (Graph Store Protocol): a committed write bumps the version"
curl -fsS -D "$OUT/load.headers" -o /dev/null -H 'Content-Type: text/turtle' --data-binary @- "$BASE/ds/data?default" <<'EOF'
PREFIX ex: <http://example.org/>
ex:alice ex:name "Alice" ; ex:email "alice@example.org" .
ex:bob   ex:name "Bob"   ; ex:email "bob@example.org" .
ex:carol ex:name "Carol" .
EOF
V1=$(header X-Dataset-Version "$OUT/load.headers")
info "X-Dataset-Version: $V1   X-Dataset-Id: $(header X-Dataset-Id "$OUT/load.headers")"

bold "2. Attested query"
info "SERVICE <urn:x-provenance:attest> { SELECT ... ORDER BY ?name }"
query "$ATTESTED_QUERY" "$OUT/results.srj" "$OUT/query.headers"
jq -r '.results.bindings[] | "   \(.name.value)\t\(.email.value // "-")\t\(.attestation.value)"' "$OUT/results.srj"
info "X-Dataset-Version: $(header X-Dataset-Version "$OUT/query.headers")"
ATTESTATION=$(jq -r '.results.bindings[0].attestation.value' "$OUT/results.srj")

bold "3. The attestation ($ATTESTATION)"
if [[ -n "$TSA_URLS" ]]; then
  # Timestamps are fetched in the background; right after the query the attestation is
  # usually still waiting for its token.
  code=$(curl -sS -D "$OUT/pending.headers" -o "$OUT/pending.json" -w '%{http_code}' \
              "$BASE/\$/provenance/attestation/${ATTESTATION#urn:uuid:}")
  if [[ "$code" == 202 ]]; then
    info "right after the query: HTTP 202, Retry-After: $(header Retry-After "$OUT/pending.headers")"
    info "$(jq -c . "$OUT/pending.json")"
  else
    info "right after the query: HTTP $code (the timestamp had already landed)"
  fi
fi
fetch_attestation "$ATTESTATION" attestation.ttl
show "$OUT/attestation.ttl"

bold "4. Independent verification (separate container, nothing from the server but the files)"
info "Checks the signature, the result digest and any RFC 3161 timestamp; the TSA certificate"
info "is chained to the JVM trust store (--tsa-trust system, the default)."
verify results.srj attestation.ttl

bold "5. Tamper with the results: change Alice's email"
jq '(.results.bindings[] | select(.name.value=="Alice") | .email.value) = "mallory@example.org"' \
   "$OUT/results.srj" > "$OUT/results-tampered.srj"
if verify results-tampered.srj attestation.ttl; then
  echo "!! tampering was NOT detected" >&2; exit 1
else
  info "-> tampering detected (exit 1), as expected"
fi

bold "6. Update: version advances; a new attestation points at the new state"
V2=$(update "$PREFIXES INSERT DATA { ex:dave ex:name \"Dave\" }")
info "update response X-Dataset-Version: $V2"
query "$ATTESTED_QUERY" "$OUT/results-2.srj" "$OUT/query-2.headers"
ATTESTATION2=$(jq -r '.results.bindings[0].attestation.value' "$OUT/results-2.srj")
fetch_attestation "$ATTESTATION2" attestation-2.ttl
verify results-2.srj attestation-2.ttl

bold "7. Empty result: an attestation-only row proves absence"
query "$PREFIXES SELECT ?p ?attestation WHERE { SERVICE <urn:x-provenance:attest> { ?p ex:name \"Mallory\" } }" \
      "$OUT/results-empty.srj" "$OUT/query-empty.headers"
jq -c '.results.bindings' "$OUT/results-empty.srj" | sed 's/^/   /'
ATTESTATION3=$(jq -r '.results.bindings[0].attestation.value' "$OUT/results-empty.srj")
fetch_attestation "$ATTESTATION3" attestation-empty.ttl
verify results-empty.srj attestation-empty.ttl

bold "8. Persistent vs TDB2-internal counter"
query "$PREFIXES SELECT (jip:dataVersion() AS ?persistent) (jip:tdbDataVersion() AS ?tdbInternal) {}" \
      "$OUT/versions.srj" "$OUT/versions.headers"
jq -c '.results.bindings[0] | {persistent: .persistent.value, tdbInternal: .tdbInternal.value}' "$OUT/versions.srj" | sed 's/^/   /'

bold "9. Restart the container: the persistent version survives, TDB2's internal one restarts at 0"
docker compose restart fuseki >/dev/null
wait_ready
curl -fsS "$BASE/\$/provenance/version/ds" | jq -c '{version, tdbInternal}' | sed 's/^/   /'
V3=$(update "$PREFIXES INSERT DATA { ex:erin ex:name \"Erin\" }")
info "after one more update: X-Dataset-Version $V3"
curl -fsS "$BASE/\$/provenance/version/ds" | jq -c '{version, tdbInternal}' | sed 's/^/   /'
[[ "$V3" -eq $((V2 + 1)) ]] || { echo "!! version did not continue after restart ($V2 -> $V3)" >&2; exit 1; }

bold "10. Attestations are queryable (PROV-O) at /provenance"
curl -fsS -H 'Accept: application/sparql-results+json' --data-urlencode query@- "$BASE/provenance/sparql" <<'EOF' |
PREFIX prov: <http://www.w3.org/ns/prov#>
PREFIX jip:  <https://larsw.xyz/jip/>
SELECT ?attestation ?version ?solutions ?ended ?tsa WHERE {
  GRAPH ?attestation {
    ?attestation jip:attests ?r .
    ?r prov:wasDerivedFrom ?state ; jip:solutionCount ?solutions ; prov:wasGeneratedBy ?exec .
    ?state jip:dataVersion ?version .
    ?exec prov:endedAtTime ?ended .
    OPTIONAL { ?attestation jip:timestamp/jip:timestampAuthority ?tsa }
  }
} ORDER BY ?ended
EOF
  jq -r '.results.bindings[] | "   v\(.version.value)\t\(.solutions.value) solution(s)\t\(.attestation.value)\t\(.tsa.value // "no timestamp")"'

if [[ -n "$TSA_URLS" ]]; then
  bold "11. Timestamp fallback: put an unreachable TSA first in the list"
  DEAD_TSA=http://127.0.0.1:9/tsr
  JIP_TSA_URLS="$DEAD_TSA $TSA_URLS" docker compose --progress quiet up -d
  wait_ready
  info "priority list is now: $DEAD_TSA $TSA_URLS"
  query "$ATTESTED_QUERY" "$OUT/results-fallback.srj" "$OUT/query-fallback.headers"
  ATTESTATION4=$(jq -r '.results.bindings[0].attestation.value' "$OUT/results-fallback.srj")
  fetch_attestation "$ATTESTATION4" attestation-fallback.ttl
  verify results-fallback.srj attestation-fallback.ttl
  docker compose logs --no-log-prefix fuseki 2>/dev/null | grep -E 'Timestamp authority .* failed|fallback authority' | tail -2 \
    | sed -e $'s/\x1b\\[[0-9;]*[A-Za-z]//g' -e 's/^/   log: /' || true
  info "(the next run of this script restores the normal list)"
fi

if [[ "$(jq -r .signer "$OUT/key.json")" == pkcs11 ]]; then
  bold "12. Restart the signer container: Fuseki reconnects to the token on the next signature"
  docker compose restart signer >/dev/null 2>&1
  for _ in $(seq 1 30); do
    [[ "$(docker compose ps --format '{{.Health}}' signer)" == healthy ]] && break
    sleep 1
  done
  query "$ATTESTED_QUERY" "$OUT/results-restart.srj" "$OUT/query-restart.headers"
  ATTESTATION5=$(jq -r '.results.bindings[0].attestation.value' "$OUT/results-restart.srj")
  fetch_attestation "$ATTESTATION5" attestation-restart.ttl
  verify results-restart.srj attestation-restart.ttl
  docker compose logs --no-log-prefix fuseki 2>/dev/null | grep -E 'reconnecting' | tail -1 \
    | sed -e $'s/\x1b\\[[0-9;]*[A-Za-z]//g' -e 's/^/   log: /' || true
fi

bold "Done. Files are in $OUT"
