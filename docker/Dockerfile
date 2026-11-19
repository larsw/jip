# syntax=docker/dockerfile:1.7
#
# Apache Jena Fuseki 6.2.0 + jena-intrinsic-provenance.
#   docker build -f docker/Dockerfile -t jena-intrinsic-provenance:0.16.0 .
# Tests run during the build (on JDK 21); skip with --build-arg SKIP_TESTS=true.

# ---- Build the modules: the Fuseki module jar and the verifier CLI jar (both shaded)
FROM maven:3.9-eclipse-temurin-21 AS build
# SoftHSM2 lets Pkcs11SignerTest sign on a real PKCS#11 token during the build.
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends softhsm2 \
 && rm -rf /var/lib/apt/lists/*
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
    | grep -aE 'Tests run:|BUILD|ERROR|FAIL' ; \
    test -f jip-fuseki/target/jena-intrinsic-provenance.jar && test -f jip-verifier-cli/target/jip-verify.jar

# ---- Runtime
# Pinned to Ubuntu 24.04 like docker/signer/Dockerfile: p11-kit-client.so here and p11-kit server
# there must be the same p11-kit version (0.25 and 0.26 don't interoperate for key generation).
FROM eclipse-temurin:21-jre-noble

LABEL org.opencontainers.image.title="jena-intrinsic-provenance" \
      org.opencontainers.image.description="Fuseki 6.2.0 with a persistent TDB2 data version and signed RDFC-1.0 result attestations (PoC)"

# Fuseki server jar from Maven Central, pinned by SHA-256 (Central only publishes SHA-1/MD5).
ADD --checksum=sha256:2c92c598e65ab69d99820052e05f4277ed1d77980a8845f87545ad35b71a76ee \
    https://repo1.maven.org/maven2/org/apache/jena/jena-fuseki-server/6.2.0/jena-fuseki-server-6.2.0.jar \
    /opt/fuseki/fuseki-server.jar

# p11-kit-client.so: the PKCS#11 module that forwards to the signer container's p11-kit server.
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends p11-kit-modules \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /opt/jip \
 && ln -s "$(find /usr/lib -name p11-kit-client.so | head -1)" /opt/jip/p11-kit-client.so

RUN useradd --system --uid 10001 --home-dir /fuseki --shell /usr/sbin/nologin fuseki \
 && mkdir -p /fuseki /opt/fuseki/lib \
 && chown fuseki:fuseki /fuseki \
 && chmod 0644 /opt/fuseki/fuseki-server.jar

COPY --from=build /build/jip-fuseki/target/jena-intrinsic-provenance.jar /opt/fuseki/lib/
COPY --from=build /build/jip-verifier-cli/target/jip-verify.jar /opt/jip/jip-verify.jar
COPY docker/config.ttl /opt/fuseki/config.ttl
COPY docker/shiro.ini /opt/fuseki/shiro.ini
COPY docker/entrypoint.sh /opt/fuseki/entrypoint.sh

# Signing: PKCS#11 through p11-kit-client.so to the signer's socket (docker-compose.yml runs the
# signer). PROVENANCE_SIGNER=local signs with the Ed25519 key file PROVENANCE_SIGNING_KEY instead.
ENV FUSEKI_BASE=/fuseki \
    PROVENANCE_SIGNER=pkcs11 \
    PROVENANCE_PKCS11_LIBRARY=/opt/jip/p11-kit-client.so \
    P11_KIT_SERVER_ADDRESS=unix:path=/run/jip-signer/pkcs11.sock \
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
