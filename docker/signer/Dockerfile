# syntax=docker/dockerfile:1.7
#
# The signer: a PKCS#11 token in its own process and container. SoftHSM2 holds the key;
# `p11-kit server` exposes the token on a Unix socket. The Fuseki container loads only
# p11-kit-client.so, which forwards every PKCS#11 call over that socket, so the private key
# never enters the Fuseki process. In production, replace SoftHSM2 with an HSM's PKCS#11 module.
#   docker build -f docker/signer/Dockerfile -t jip-signer:0.12.0 .
# Same Ubuntu release as the Fuseki runtime image (eclipse-temurin:21-jre-noble): the p11-kit
# server here and p11-kit-client.so there must be the same p11-kit version.
FROM ubuntu:24.04

LABEL org.opencontainers.image.title="jip-signer" \
      org.opencontainers.image.description="SoftHSM2 token served over a Unix socket by p11-kit server (jena-intrinsic-provenance PoC)"

RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends softhsm2 p11-kit \
 && rm -rf /var/lib/apt/lists/* \
 && ln -s "$(find /usr/lib -name libsofthsm2.so | head -1)" /usr/local/lib/libsofthsm2.so \
 && useradd --system --uid 10001 --home-dir /var/lib/jip-signer --shell /usr/sbin/nologin signer \
 && mkdir -p /var/lib/jip-signer/tokens /run/jip-signer \
 && chown -R signer:signer /var/lib/jip-signer /run/jip-signer

COPY docker/signer/entrypoint.sh /usr/local/bin/jip-signer

# Same uid as the fuseki user, so the Fuseki container can use the socket.
USER signer
VOLUME /var/lib/jip-signer

HEALTHCHECK --interval=2s --timeout=2s --start-period=10s --retries=15 \
  CMD test -S /run/jip-signer/pkcs11.sock || exit 1

ENTRYPOINT ["/usr/local/bin/jip-signer"]
