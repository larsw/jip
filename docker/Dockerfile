# syntax=docker/dockerfile:1.7
#
# Apache Jena Fuseki 6.2.0 + jena-intrinsic-provenance.
#   docker build -f docker/Dockerfile -t jena-intrinsic-provenance:0.11.0 .
# Tests run during the build (on JDK 21); skip with --build-arg SKIP_TESTS=true.

# ---- Build the modules: the Fuseki module jar and the verifier CLI jar (both shaded)
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /build
COPY pom.xml ./
COPY jip-verifier/pom.xml ./jip-verifier/
COPY jip-verifier-cli/pom.xml ./jip-verifier-cli/
COPY jip-fuseki/pom.xml ./jip-fuseki/
RUN --mount=type=cache,target=/root/.m2 mvn -B -q dependency:go-offline || true
COPY jip-verifier/src ./jip-verifier/src
COPY jip-verifier-cli/src ./jip-verifier-cli/src
COPY jip-fuseki/src ./jip-fuseki/src
COPY docker/config.ttl ./docker/config.ttl
COPY vocab ./vocab
ARG SKIP_TESTS=false
RUN --mount=type=cache,target=/root/.m2 mvn -B package -DskipTests=${SKIP_TESTS} 2>&1 \
    | grep -E 'Tests run:|BUILD|ERROR|FAIL' ; \
    test -f jip-fuseki/target/jena-intrinsic-provenance.jar && test -f jip-verifier-cli/target/jip-verify.jar

# ---- Runtime
FROM eclipse-temurin:21-jre

LABEL org.opencontainers.image.title="jena-intrinsic-provenance" \
      org.opencontainers.image.description="Fuseki 6.2.0 with a persistent TDB2 data version and signed RDFC-1.0 result certificates (PoC)"

# Fuseki server jar from Maven Central, pinned by SHA-256 (Central only publishes SHA-1/MD5).
ADD --checksum=sha256:2c92c598e65ab69d99820052e05f4277ed1d77980a8845f87545ad35b71a76ee \
    https://repo1.maven.org/maven2/org/apache/jena/jena-fuseki-server/6.2.0/jena-fuseki-server-6.2.0.jar \
    /opt/fuseki/fuseki-server.jar

RUN useradd --system --uid 10001 --home-dir /fuseki --shell /usr/sbin/nologin fuseki \
 && mkdir -p /fuseki /opt/fuseki/lib \
 && chown fuseki:fuseki /fuseki \
 && chmod 0644 /opt/fuseki/fuseki-server.jar

COPY --from=build /build/jip-fuseki/target/jena-intrinsic-provenance.jar /opt/fuseki/lib/
COPY --from=build /build/jip-verifier-cli/target/jip-verify.jar /opt/jip/jip-verify.jar
COPY docker/config.ttl /opt/fuseki/config.ttl
COPY docker/shiro.ini /opt/fuseki/shiro.ini
COPY docker/entrypoint.sh /opt/fuseki/entrypoint.sh

ENV FUSEKI_BASE=/fuseki \
    PROVENANCE_SIGNING_KEY=/fuseki/provenance/signing-key.pem \
    JAVA_OPTIONS="-Xmx1g"

USER fuseki
WORKDIR /fuseki
VOLUME /fuseki
EXPOSE 3030

HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=3 \
  CMD curl -fsS http://localhost:3030/\$/ping > /dev/null || exit 1

ENTRYPOINT ["/opt/fuseki/entrypoint.sh"]
CMD ["server"]
