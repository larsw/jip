#!/usr/bin/env bash
# End-to-end demo of jena-intrinsic-provenance against the Docker image.
#
#   scripts/demo.sh [--reset] [--tsa "<url> [<url>...]"] [--no-tsa]
#
#   --reset    delete the demo's Docker volume first (databases, signing key)
#   --tsa      RFC 3161 timestamp authorities, in priority order (default: $TSA_DEFAULT,
#              or $JIP_TSA_URLS if set)
#   --no-tsa   issue certificates without timestamps
#
# Needs: docker (compose v2), curl, jq. Writes files to ./demo-out.
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
BASE=http://localhost:3030
IMAGE=jena-intrinsic-provenance:0.10.0
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

# verify <results> <certificate>  -> prints report, returns verifier exit status
verify() {
  docker run --rm -v "$OUT:/data:ro" "$IMAGE" verify \
    --results "/data/$1" --cert "/data/$2" --expect-key "$DID" | sed 's/^/   | /'
  return "${PIPESTATUS[0]}"
}

# certificate <cert-iri> <file>
certificate() {
  curl -fsS -H 'Accept: text/turtle' "$BASE/\$/provenance/certificate/${1#urn:uuid:}" -o "$OUT/$2"
}

# show <file>: print a certificate, eliding the long base64 timestamp token
show() {
  sed -E 's/"([A-Za-z0-9+\/=]{48})[A-Za-z0-9+\/=]{16,}"/"\1..."/' "$1" | sed 's/^/   /'
}

PREFIXES='PREFIX ex: <http://example.org/>
PREFIX jip: <https://larsw.xyz/jip/>'
CERTIFIED_QUERY="$PREFIXES
SELECT ?name ?email ?cert WHERE {
  SERVICE <urn:x-provenance:certify> {
    SELECT ?name ?email WHERE { ?p ex:name ?name OPTIONAL { ?p ex:email ?email } } ORDER BY ?name
  }
}"

# ---------------------------------------------------------------------------
if [[ -n "$RESET" ]]; then
  bold "Reset: removing the demo volume"
  docker compose down -v
fi

bold "Build and start Fuseki 6.2.0 + module"
docker compose --progress quiet up -d --build
wait_ready
DID=$(curl -fsS "$BASE/\$/provenance/key" | jq -r .id)
info "signing key: $DID"
V0=$(curl -fsS "$BASE/\$/provenance/version/ds" | jq -r .version)
info "persistent data version of /ds: $V0"
if [[ -n "$TSA_URLS" ]]; then
  info "timestamp authorities (priority order): $TSA_URLS"
else
  info "timestamp authorities: none (certificates are not timestamped)"
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

bold "2. Certified query"
info "SERVICE <urn:x-provenance:certify> { SELECT ... ORDER BY ?name }"
query "$CERTIFIED_QUERY" "$OUT/results.srj" "$OUT/query.headers"
jq -r '.results.bindings[] | "   \(.name.value)\t\(.email.value // "-")\t\(.cert.value)"' "$OUT/results.srj"
info "X-Dataset-Version: $(header X-Dataset-Version "$OUT/query.headers")"
CERT=$(jq -r '.results.bindings[0].cert.value' "$OUT/results.srj")

bold "3. The certificate ($CERT)"
certificate "$CERT" certificate.ttl
show "$OUT/certificate.ttl"

bold "4. Independent verification (separate container, nothing from the server but the files)"
info "Checks the signature, the result digest and any RFC 3161 timestamp; the TSA certificate"
info "is chained to the JVM trust store (--tsa-trust system, the default)."
verify results.srj certificate.ttl

bold "5. Tamper with the results: change Alice's email"
jq '(.results.bindings[] | select(.name.value=="Alice") | .email.value) = "mallory@example.org"' \
   "$OUT/results.srj" > "$OUT/results-tampered.srj"
if verify results-tampered.srj certificate.ttl; then
  echo "!! tampering was NOT detected" >&2; exit 1
else
  info "-> tampering detected (exit 1), as expected"
fi

bold "6. Update: version advances; a new certificate points at the new state"
V2=$(update "$PREFIXES INSERT DATA { ex:dave ex:name \"Dave\" }")
info "update response X-Dataset-Version: $V2"
query "$CERTIFIED_QUERY" "$OUT/results-2.srj" "$OUT/query-2.headers"
CERT2=$(jq -r '.results.bindings[0].cert.value' "$OUT/results-2.srj")
certificate "$CERT2" certificate-2.ttl
verify results-2.srj certificate-2.ttl

bold "7. Empty result: a certificate-only row proves absence"
query "$PREFIXES SELECT ?p ?cert WHERE { SERVICE <urn:x-provenance:certify> { ?p ex:name \"Mallory\" } }" \
      "$OUT/results-empty.srj" "$OUT/query-empty.headers"
jq -c '.results.bindings' "$OUT/results-empty.srj" | sed 's/^/   /'
CERT3=$(jq -r '.results.bindings[0].cert.value' "$OUT/results-empty.srj")
certificate "$CERT3" certificate-empty.ttl
verify results-empty.srj certificate-empty.ttl

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

bold "10. Certificates are queryable (PROV-O) at /provenance"
curl -fsS -H 'Accept: application/sparql-results+json' --data-urlencode query@- "$BASE/provenance/sparql" <<'EOF' |
PREFIX prov: <http://www.w3.org/ns/prov#>
PREFIX jip:  <https://larsw.xyz/jip/>
SELECT ?cert ?version ?solutions ?ended ?tsa WHERE {
  GRAPH ?cert {
    ?cert jip:certifies ?r .
    ?r prov:wasDerivedFrom ?state ; jip:solutionCount ?solutions ; prov:wasGeneratedBy ?exec .
    ?state jip:dataVersion ?version .
    ?exec prov:endedAtTime ?ended .
    OPTIONAL { ?cert jip:timestamp/jip:timestampAuthority ?tsa }
  }
} ORDER BY ?ended
EOF
  jq -r '.results.bindings[] | "   v\(.version.value)\t\(.solutions.value) solution(s)\t\(.cert.value)\t\(.tsa.value // "no timestamp")"'

if [[ -n "$TSA_URLS" ]]; then
  bold "11. Timestamp fallback: put an unreachable TSA first in the list"
  DEAD_TSA=http://127.0.0.1:9/tsr
  JIP_TSA_URLS="$DEAD_TSA $TSA_URLS" docker compose --progress quiet up -d
  wait_ready
  info "priority list is now: $DEAD_TSA $TSA_URLS"
  query "$CERTIFIED_QUERY" "$OUT/results-fallback.srj" "$OUT/query-fallback.headers"
  CERT4=$(jq -r '.results.bindings[0].cert.value' "$OUT/results-fallback.srj")
  certificate "$CERT4" certificate-fallback.ttl
  verify results-fallback.srj certificate-fallback.ttl
  docker compose logs --no-log-prefix fuseki 2>/dev/null | grep -E 'Timestamp authority .* failed|fallback authority' | tail -2 \
    | sed -e $'s/\x1b\\[[0-9;]*[A-Za-z]//g' -e 's/^/   log: /' || true
  info "(the next run of this script restores the normal list)"
fi

bold "Done. Files are in $OUT"
