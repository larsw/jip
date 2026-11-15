# jena-intrinsic-provenance

A proof of concept for Apache Jena and Fuseki 6.2.0 (Java 21). It adds two things:

- A persistent data version for TDB2. It goes up by one on every committed write transaction
  and survives restarts, compaction, and crashes.
- Signed provenance certificates for SPARQL results. Wrap a pattern in
  `SERVICE <urn:x-provenance:certify>` and every row comes back with a certificate IRI. The
  certificate is a PROV-O graph that records the data version the rows were read from and a
  digest of the rows, computed with RDF Dataset Canonicalization
  ([RDFC-1.0](https://www.w3.org/TR/rdf-canon/)). It is signed with the W3C Data Integrity
  cryptosuite `eddsa-rdfc-2022`.

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
the version continues from where it stopped.

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

docker run --rm -v "$PWD:/data:ro" jena-intrinsic-provenance:0.1.0 \
  verify --results /data/results.srj --cert /data/certificate.ttl --expect-key did:key:z6Mk…
```

The verifier exits with 0 if the certificate is valid, 1 if it is not, and 2 on bad input.

The service IRI takes two optional parameters:

| Parameter | Effect |
|---|---|
| `var=name` | Bind the certificate to `?name` instead of `?cert` |
| `empty=row` (default) | An empty result gives one row that carries only the certificate |
| `empty=none` | An empty result gives no rows and no certificate |

The data version is available in four places:

- `jip:dataVersion()` returns the version of the snapshot the query reads
  (`PREFIX jip: <http://example.org/jip#>`).
- `jip:tdbDataVersion()` returns TDB2's own in-memory counter, which restarts at 0.
- `GET /$/provenance/version/{dataset}` returns both as JSON.
- Responses that read or wrote a versioned dataset carry the `X-Dataset-Version` and
  `X-Dataset-Id` headers.

## Configuration

Declare the dataset as `jip:VersionedDatasetTDB2` instead of `tdb2:DatasetTDB2`, and name a
separate TDB2 location for the certificates (see [`docker/config.ttl`](docker/config.ttl)):

```turtle
[] a fuseki:Server ;
   ja:context [ ja:cxtName "http://example.org/jip#certificateStore" ; ja:cxtValue "/fuseki/databases/provenance" ] ;
   ja:context [ ja:cxtName "http://example.org/jip#maxSolutions"    ; ja:cxtValue "10000" ] .

:dataset a jip:VersionedDatasetTDB2 ;
    tdb2:location "/fuseki/databases/ds" ;
    jip:datasetIRI <https://example.org/datasets/ds> .   # optional
```

The signing key is an Ed25519 PKCS#8 PEM file. Its path comes from the `PROVENANCE_SIGNING_KEY`
environment variable or the `jip.signingKey` system property, and defaults to
`$FUSEKI_BASE/provenance/signing-key.pem`. If the file doesn't exist, the server creates a key
on first start.

| Endpoint | Returns |
|---|---|
| `GET /$/provenance/certificate/{uuid}` | The certificate as Turtle, JSON-LD, N-Triples, N-Quads, or RDF/XML |
| `GET /$/provenance/key` | The public key as a `did:key`, multibase, JWK, and PEM |
| `GET /$/provenance/version/{dataset}` | The persistent and internal data versions |

## Building

```bash
mvn package                      # target/jena-intrinsic-provenance.jar (Jena itself is not bundled)
scripts/build-whitepaper.sh      # docs/whitepaper/build/whitepaper.pdf (needs TeX Live with latexmk)
```

To use the module with your own Fuseki 6.2.0, put the jar on the classpath next to
`fuseki-server.jar`. [`docker/entrypoint.sh`](docker/entrypoint.sh) shows the command line.

## Limitations

- Tools that write to the database from another JVM without this module, such as
  `tdb2.tdbloader`, don't advance the version.
- Anyone who can run a query can create certificates, and each certificate is a write to the
  certificate store. Add authentication or rate limiting before real use.
- Timestamps come from the server clock.
- The proof is stored as RDF triples, so JSON-LD Verifiable Credential tools may not accept it.
- A refused certification (no version, too many rows, inside a write transaction) is reported
  as HTTP 500.
- The `jip:` namespace (`http://example.org/jip#`) and the Maven coordinates
  `org.example.jena:jena-intrinsic-provenance` are placeholders.

## Layout

```
src/main/java/org/example/jena/provenance/
  version/    persistent data version (transaction component, journal recovery, assembler)
  canon/      RDFC-1.0 adapter and the result-set encoding
  cert/       certificate builder, signing, key handling, store, verifier
  service/    the certify SERVICE executor
  function/   jip:dataVersion(), jip:tdbDataVersion()
  fuseki/     Fuseki module, HTTP endpoints, header filter
  cli/        offline verifier
docker/       Dockerfile, Fuseki configuration, shiro.ini, entrypoint
docs/         design notes and the whitepaper
scripts/      demo and whitepaper build
```
