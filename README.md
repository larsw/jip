# jena-intrinsic-provenance

A proof of concept for Apache Jena and Fuseki 6.2.0 (Java 21). It adds two things:

- A persistent data version for TDB2. It goes up by one on every committed write transaction
  and survives restarts, compaction, and crashes.
- Signed provenance certificates for SPARQL results. Wrap a pattern in
  `SERVICE <urn:x-provenance:certify>` and every row comes back with a certificate IRI. The
  certificate is a PROV-O graph that records the data version the rows were read from and a
  digest of the rows, computed with RDF Dataset Canonicalization
  ([RDFC-1.0](https://www.w3.org/TR/rdf-canon/)). It is signed with the W3C Data Integrity
  cryptosuite `eddsa-rdfc-2022` and can be co-signed by an RFC 3161 timestamp authority (TSA).

The whitepaper in [`docs/whitepaper/`](docs/whitepaper/) explains the findings, the design,
and the measurements; `scripts/build-whitepaper.sh` builds the PDF.
[`docs/DESIGN.md`](docs/DESIGN.md) lists the design decisions.

## Quick start

```bash
docker compose up -d --build    # builds the module, runs the tests, starts Fuseki on :3030
scripts/demo.sh --reset         # end-to-end demo; needs curl and jq
```

The demo loads data, runs a certified query, and verifies the certificate in a separate
container. A tampered copy of the result then fails verification, and after a container restart
the version continues from where it stopped. Certificates are timestamped by public TSAs
(DigiCert, then Sectigo, then FreeTSA); pick others with `--tsa "<url> <url>"` or
`JIP_TSA_URLS`, or turn timestamps off with `--no-tsa`. The last step puts an unreachable TSA
first in the list to show the fallback.

## Using it

A certified query:

```sparql
PREFIX ex: <http://example.org/>
SELECT ?name ?email ?cert WHERE {
  SERVICE <urn:x-provenance:certify> {
    SELECT ?name ?email WHERE { ?p ex:name ?name OPTIONAL { ?p ex:email ?email } } ORDER BY ?name
  }
}
```

Every row has `?cert` bound to the same `<urn:uuid:…>`. Project `?cert` explicitly, because
`SELECT *` leaves it out. Fetch the certificate and check it offline:

```bash
curl -H 'Accept: text/turtle' "http://localhost:3030/\$/provenance/certificate/<uuid>" > certificate.ttl

docker run --rm -v "$PWD:/data:ro" jena-intrinsic-provenance:0.10.0 \
  verify --results /data/results.srj --cert /data/certificate.ttl --expect-key did:key:z6Mk…
```

The verifier exits with 0 if the certificate is valid, 1 if it is not, and 2 on bad input.
It also checks RFC 3161 timestamps on the certificate. `--tsa-trust` says what the TSA's
certificate must chain to: `system` (the JVM trust store, the default), a PEM file of CA
certificates, or `none` to skip the chain check. An untrusted timestamp is reported but only
fails verification with `--require-timestamp`.
Without Docker, run the standalone jar the build produces:

```bash
java -jar jip-verifier-cli/target/jip-verify.jar -r results.srj -c certificate.ttl -k did:key:z6Mk…
```

To verify from your own Java code, depend on `xyz.larsw:jip-verifier`. It needs `jena-arq`,
titanium-rdfc and BouncyCastle, not TDB2 or Fuseki:

```java
CertificateVerifier.Report report =
    CertificateVerifier.verify(Path.of("certificate.ttl"), Path.of("results.srj"), Optional.of(trustedDidKey));
if ( !report.valid() )
    report.problems().forEach(System.err::println);
```

`CertificateVerifier.verify(Graph, RowSet, Optional)` takes a parsed certificate and the rows of a
query execution instead of files. The overloads that take `CertificateVerifier.Options` set the
TSA trust anchors and whether a timestamp is required.

The service IRI takes two optional parameters:

| Parameter | Effect |
|---|---|
| `var=name` | Bind the certificate to `?name` instead of `?cert` |
| `empty=row` (default) | An empty result gives one row that carries only the certificate |
| `empty=none` | An empty result gives no rows and no certificate |

The data version is available in four places:

- `jip:dataVersion()` returns the version of the snapshot the query reads
  (`PREFIX jip: <https://larsw.xyz/jip/>`; the terms are defined in
  [`vocab/jip.ttl`](vocab/jip.ttl) and published at <https://larsw.xyz/jip/>).
- `jip:tdbDataVersion()` returns TDB2's own in-memory counter, which restarts at 0.
- `GET /$/provenance/version/{dataset}` returns both as JSON.
- Responses that read or wrote a versioned dataset carry the `X-Dataset-Version` and
  `X-Dataset-Id` headers.

## Configuration

Declare the dataset as `jip:VersionedDatasetTDB2` instead of `tdb2:DatasetTDB2`, and name a
separate TDB2 location for the certificates (see [`docker/config.ttl`](docker/config.ttl)):

```turtle
[] a fuseki:Server ;
   ja:context [ ja:cxtName "https://larsw.xyz/jip/certificateStore" ; ja:cxtValue "/fuseki/databases/provenance" ] ;
   ja:context [ ja:cxtName "https://larsw.xyz/jip/maxSolutions"    ; ja:cxtValue "10000" ] .

:dataset a jip:VersionedDatasetTDB2 ;
    tdb2:location "/fuseki/databases/ds" ;
    jip:datasetIRI <https://example.org/datasets/ds> .   # optional
```

The signing key is an Ed25519 PKCS#8 PEM file. Its path comes from the `PROVENANCE_SIGNING_KEY`
environment variable or the `jip.signingKey` system property, and defaults to
`$FUSEKI_BASE/provenance/signing-key.pem`. If the file doesn't exist, the server creates a key
on first start.

### Timestamps (RFC 3161)

Optionally, a time-stamping authority co-signs every certificate. The TSA signs SHA-256 of the
certificate's Ed25519 signature, so the token proves the certificate existed at the TSA's time
and does not depend on the server clock. The token is stored in the certificate as a
`jip:timestamp` node, outside the signed document (see [`docs/DESIGN.md`](docs/DESIGN.md#timestamps-rfc-3161)).

| Context setting (`ja:context`) | Environment (overrides) | Value |
|---|---|---|
| `jip:timestampAuthorities` | `PROVENANCE_TSA_URLS` | TSA URLs in priority order, separated by spaces or commas. Unset or empty: no timestamps. |
| `jip:timestampPolicy` | `PROVENANCE_TSA_POLICY` | `optional` (default): issue the certificate without a timestamp if no TSA answers. `required`: fail the query. |
| `jip:timestampTimeout` | `PROVENANCE_TSA_TIMEOUT` | Milliseconds allowed per TSA (default 5000). |

The TSAs are tried in order and the first valid token is used. A TSA that fails is tried last
for the next 60 seconds, so one that is down doesn't slow down every certificate.

| Endpoint | Returns |
|---|---|
| `GET /$/provenance/certificate/{uuid}` | The certificate as Turtle, JSON-LD, N-Triples, N-Quads, or RDF/XML |
| `GET /$/provenance/key` | The public key as a `did:key`, multibase, JWK, and PEM |
| `GET /$/provenance/version/{dataset}` | The persistent and internal data versions |

## Building

```bash
mvn package                      # all three modules, see the table below
scripts/build-whitepaper.sh      # docs/whitepaper/build/whitepaper.pdf (needs TeX Live with latexmk)
```

| Jar | What it is |
|---|---|
| `jip-fuseki/target/jena-intrinsic-provenance.jar` | The Fuseki module. Jena itself is not bundled; the verifier library, titanium-rdfc (relocated) and BouncyCastle's bcpkix/bcutil are. It uses the bcprov in Fuseki's server jar. |
| `jip-verifier-cli/target/jip-verify.jar` | The offline verifier, self-contained (`java -jar`). |
| `jip-verifier/target/jip-verifier-0.10.0.jar` | The verifier library, for use as a Maven dependency. |

To use the module with your own Fuseki 6.2.0, put `jena-intrinsic-provenance.jar` on the classpath next to
`fuseki-server.jar`. [`docker/entrypoint.sh`](docker/entrypoint.sh) shows the command line.

## Limitations

- Tools that write to the database from another JVM without this module, such as
  `tdb2.tdbloader`, don't advance the version.
- Anyone who can run a query can create certificates, and each certificate is a write to the
  certificate store. Add authentication or rate limiting before real use.
- Without a TSA, timestamps come from the server clock. With one, the TSA vouches for the time
  the certificate was signed, but the times inside the certificate (`prov:startedAtTime` etc.)
  are still the server's. TSA certificates are not checked for revocation.
- Every certificate that is timestamped costs one outgoing HTTP request, made while the query
  runs. Public TSAs rate-limit, so use your own or a contracted TSA for real loads.
- The proof is stored as RDF triples, so JSON-LD Verifiable Credential tools may not accept it.
- A refused certification (no version, too many rows, inside a write transaction) is reported
  as HTTP 500.

## Layout

```
pom.xml             parent (jena-intrinsic-provenance-parent)
jip-verifier/       verifier library; depends on jena-arq, titanium-rdfc and BouncyCastle
  src/main/java/xyz/larsw/jip/
    canon/    RDFC-1.0 adapter and the result-set encoding
    cert/     CertificateVerifier, Data Integrity proofs, did:key, RFC 3161 tokens, vocabulary terms
jip-verifier-cli/   the offline verifier command (cli/Verify), packaged as jip-verify.jar
jip-fuseki/         the Fuseki module (artifact jena-intrinsic-provenance); uses jip-verifier
  src/main/java/xyz/larsw/jip/
    version/  persistent data version (transaction component, journal recovery, assembler)
    cert/     certificate builder, signing key, key handling, store, TSA client
    service/  the certify SERVICE executor
    function/ jip:dataVersion(), jip:tdbDataVersion()
    fuseki/   Fuseki module, HTTP endpoints, header filter
docker/       Dockerfile, Fuseki configuration, shiro.ini, entrypoint
docs/         design notes and the whitepaper
vocab/        jip.ttl, the jip: vocabulary (RDFS/OWL)
scripts/      demo, whitepaper build, vocabulary site build
.github/      workflow that publishes the vocabulary with GitHub Pages
```
