#!/bin/sh
# Container entrypoint.
#   server [fuseki args...]   run Fuseki with the provenance module (default)
#   verify [verify args...]   run the independent certificate verifier (standalone jar,
#                             not on Fuseki's classpath)
#   <anything else>           exec it
set -eu

CP="/opt/fuseki/fuseki-server.jar:/opt/fuseki/lib/*"
cmd="${1:-server}"
[ "$#" -gt 0 ] && shift

case "$cmd" in
  server)
    mkdir -p "${FUSEKI_BASE}/databases" "$(dirname "${PROVENANCE_SIGNING_KEY}")"
    # Fuseki writes a default shiro.ini (admin area incl. /$/provenance localhost-only) if none exists.
    [ -f "${FUSEKI_BASE}/shiro.ini" ] || cp /opt/fuseki/shiro.ini "${FUSEKI_BASE}/shiro.ini"
    # JAVA_OPTIONS is intentionally unquoted: it holds several JVM flags.
    # shellcheck disable=SC2086
    exec java ${JAVA_OPTIONS:-} -cp "$CP" org.apache.jena.fuseki.main.cmds.FusekiServerCmd \
         --config="${FUSEKI_CONFIG:-/opt/fuseki/config.ttl}" "$@"
    ;;
  verify)
    exec java -jar /opt/jip/jip-verify.jar "$@"
    ;;
  *)
    exec "$cmd" "$@"
    ;;
esac
