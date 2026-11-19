# jena-intrinsic-provenance

A proof of concept for Apache Jena and Fuseki 6.2.0 (Java 21). It adds two things:

- A persistent data version for TDB2. It goes up by one on every committed write transaction
  and survives restarts, compaction, and crashes.
- Signed provenance attestations for SPARQL results. Wrap a pattern in
  `SERVICE <urn:x-provenance:attest>` and every row comes back with an attestation IRI. The
  attestation is a PROV-O graph that records the data version the rows were read from and a
  digest of the rows, computed with RDF Dataset Canonicalization
  ([RDFC-1.0](https://www.w3.org/TR/rdf-canon/)). It is signed with the W3C Data Integrity
  cryptosuite `ecdsa-rdfc-2019` (P-256 or P-384 key on a PKCS#11 token, by default in a
  separate signer process) or `eddsa-rdfc-2022` (Ed25519 key file, opt-in), and can be co-signed
  by an RFC 3161 timestamp authority (TSA).

A note on names: the signed statements are *result attestations*, and a query that asks for one
is an *attested query*. "Certificate" only ever means an X.509 certificate, such as a
time-stamping authority's.

The whitepaper in [`docs/whitepaper/`](docs/whitepaper/) explains the findings, the design,
and the measurements; `scripts/build-whitepaper.sh` builds the PDF.
[`docs/DESIGN.md`](docs/DESIGN.md) lists the design decisions.

## Quick start

```bash
docker compose up -d --build    # builds the module, runs the tests, starts Fuseki on :3030
scripts/demo.sh --reset         # end-to-end demo; needs curl and jq
```

The demo loads data, runs an attested query, and verifies the attestation in a separate
container. A tampered copy of the result then fails verification, and after a container restart
the version continues from where it stopped. Attestations are timestamped by public TSAs
(DigiCert, then Sectigo, then FreeTSA); pick others with `--tsa "<url> <url>"` or
`JIP_TSA_URLS`, or turn timestamps off with `--no-tsa`. The last step puts an unreachable TSA
first in the list to show the fallback.

## Using it

An attested query:

```sparql
PREFIX ex: <http://example.org/>
SELECT ?name ?email ?attestation WHERE {
  SERVICE <urn:x-provenance:attest> {
    SELECT ?name ?email WHERE { ?p ex:name ?name OPTIONAL { ?p ex:email ?email } } ORDER BY ?name
  }
}
```

Every row has `?attestation` bound to the same `<urn:uuid:…>`. Project `?attestation` explicitly, because
`SELECT *` leaves it out. Fetch the attestation and check it offline:

```bash
curl -H 'Accept: text/turtle' "http://localhost:3030/\$/provenance/attestation/<uuid>" > attestation.ttl

docker run --rm -v "$PWD:/data:ro" jena-intrinsic-provenance:0.13.0 \
  verify --results /data/results.srj --attestation /data/attestation.ttl --expect-key did:key:zDn…
```

The verifier exits with 0 if the attestation is valid, 1 if it is not, and 2 on bad input.
It also checks RFC 3161 timestamps on the attestation. `--tsa-trust` says what the TSA's
certificate must chain to: `system` (the JVM trust store, the default), a PEM file of CA
certificates, or `none` to skip the chain check. An untrusted timestamp is reported but only
fails verification with `--require-timestamp`.
Without Docker, run the standalone jar the build produces:

```bash
java -jar jip-verifier-cli/target/jip-verify.jar -r results.srj -a attestation.ttl -k did:key:zDn…
```

To verify from your own Java code, depend on `xyz.larsw:jip-verifier`. It needs `jena-arq`,
titanium-rdfc and BouncyCastle, not TDB2 or Fuseki:

```java
AttestationVerifier.Report report =
    AttestationVerifier.verify(Path.of("attestation.ttl"), Path.of("results.srj"), Optional.of(trustedDidKey));
if ( !report.valid() )
    report.problems().forEach(System.err::println);
```

`AttestationVerifier.verify(Graph, RowSet, Optional)` takes a parsed attestation and the rows of a
query execution instead of files. The overloads that take `AttestationVerifier.Options` set the
TSA trust anchors and whether a timestamp is required.

The service IRI takes two optional parameters:

| Parameter | Effect |
|---|---|
| `var=name` | Bind the attestation to `?name` instead of `?attestation` |
| `empty=row` (default) | An empty result gives one row that carries only the attestation |
| `empty=none` | An empty result gives no rows and no attestation |

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
separate TDB2 location for the attestations (see [`docker/config.ttl`](docker/config.ttl)):

```turtle
[] a fuseki:Server ;
   ja:context [ ja:cxtName "https://larsw.xyz/jip/attestationStore" ; ja:cxtValue "/fuseki/databases/provenance" ] ;
   ja:context [ ja:cxtName "https://larsw.xyz/jip/maxSolutions"    ; ja:cxtValue "10000" ] .

:dataset a jip:VersionedDatasetTDB2 ;
    tdb2:location "/fuseki/databases/ds" ;
    jip:datasetIRI <https://example.org/datasets/ds> .   # optional
```

### Signing

The signer is chosen with `PROVENANCE_SIGNER` (or the system property `jip.signer`):

- **`pkcs11` (default)**: an ECDSA P-256 or P-384 key on a PKCS#11 token, used through the
  JDK's SunPKCS11 provider; attestations use the cryptosuite `ecdsa-rdfc-2019`. The private key
  never enters the Fuseki process: every signature is a `C_Sign` call into the token. The
  PKCS#11 module can be an HSM vendor's library, SoftHSM, or `p11-kit-client.so`, which
  forwards the calls over a Unix socket to a `p11-kit server` in another process.
- **`local` (opt-in)**: an Ed25519 key in a PKCS#8 PEM file, `eddsa-rdfc-2022`. The path comes
  from `PROVENANCE_SIGNING_KEY` (or `jip.signingKey`) and defaults to
  `$FUSEKI_BASE/provenance/signing-key.pem`; a key is created on first start if the file is
  missing.

| PKCS#11 setting (environment / system property) | Value |
|---|---|
| `PROVENANCE_PKCS11_LIBRARY` / `jip.pkcs11.library` | The PKCS#11 module (required, unless a config file is given) |
| `PROVENANCE_PKCS11_SLOT_INDEX` / `jip.pkcs11.slotIndex` | Index in the module's slot list (default 0) |
| `PROVENANCE_PKCS11_CONFIG` / `jip.pkcs11.config` | A SunPKCS11 configuration file, instead of the two above |
| `PROVENANCE_PKCS11_PIN`, `PROVENANCE_PKCS11_PIN_FILE` | The user PIN, directly or in a file (Docker secrets) |
| `PROVENANCE_PKCS11_KEY` / `jip.pkcs11.key` | The key's label (default `jip-signing`) |
| `PROVENANCE_PKCS11_GENERATE` / `jip.pkcs11.generate` | `P-256` or `P-384`: create the key on the token if it is missing |

A key created by the module gets a self-signed certificate next to it, because the JDK's PKCS#11
key store only lists private keys that have one. A key you create yourself needs one too, with
the same `CKA_ID`. Java 21's SunPKCS11 can't use Ed25519 keys, so PKCS#11 keys are ECDSA. If a
signature fails because the token connection was lost (the signer process restarted), the module
reconnects once and retries.

Other mechanisms (a cloud KMS, a remote signing service) can be added as a `SignerProvider`,
registered with `ServiceLoader`, and selected by name.

In Docker Compose, the `signer` service is a SoftHSM2 token served by `p11-kit server` on a
socket in a shared volume, with no network. The Fuseki image loads `/opt/jip/p11-kit-client.so`
(`P11_KIT_SERVER_ADDRESS=unix:path=/run/jip-signer/pkcs11.sock`). On first start the signer
initializes its token, and the module creates the key on it (`JIP_PKCS11_CURVE`, default
P-256). `JIP_SIGNER=local` switches to a key file. SoftHSM2 keeps keys in files, so it stands in
for an HSM here; in production, point `PROVENANCE_PKCS11_LIBRARY` (or the signer's
`p11-kit server`) at the HSM's module.

### Timestamps (RFC 3161)

Optionally, a time-stamping authority co-signs every attestation. The TSA signs SHA-256 of the
attestation's Ed25519 signature, so the token proves the attestation existed at the TSA's time
and does not depend on the server clock. The token is stored in the attestation as a
`jip:timestamp` node, outside the signed document (see [`docs/DESIGN.md`](docs/DESIGN.md#timestamps-rfc-3161)).

| Context setting (`ja:context`) | Environment (overrides) | Value |
|---|---|---|
| `jip:timestampAuthorities` | `PROVENANCE_TSA_URLS` | TSA URLs in priority order, separated by spaces or commas. Unset or empty: no timestamps. |
| `jip:timestampMode` | `PROVENANCE_TSA_MODE` | `async` (default): the query doesn't wait; the timestamp is added in the background. `sync`: the query waits for it. |
| `jip:timestampPolicy` | `PROVENANCE_TSA_POLICY` | `optional` (default): if no TSA answers, keep the attestation without a timestamp (async: after the maximum wait). `required`: keep retrying (async) or fail the query (sync). |
| `jip:timestampTimeout` | `PROVENANCE_TSA_TIMEOUT` | Milliseconds allowed per TSA (default 5000). |
| `jip:timestampMaxWait` | `PROVENANCE_TSA_MAX_WAIT` | Async, optional policy: how long to keep retrying, in milliseconds (default 600000). |

The TSAs are tried in order and the first valid token is used. A TSA that fails is tried last
for the next 60 seconds, so one that is down doesn't slow down every attestation.

In async mode the attestation is signed and stored when the query runs, and a background worker
fetches the token (retrying after 5 s, 15 s, 30 s, 1, 2, 5, then every 10 minutes). Until the
token has landed, `GET /$/provenance/attestation/{uuid}` answers **`202 Accepted`** with a
`Retry-After` header (seconds until the next attempt) and a JSON body such as
`{"attestation": "urn:uuid:…", "status": "timestamp-pending", "pendingSince": "…", "retryAfter": 3}`;
then it answers 200 with the timestamped attestation. Pending attestations are recorded in the
attestation store, so a restart resumes them. The read-only `/provenance` SPARQL endpoint shows
a pending attestation already, without its timestamp; the graph
`<https://larsw.xyz/jip/pendingTimestamps>` lists the ones still waiting.

| Endpoint | Returns |
|---|---|
| `GET /$/provenance/attestation/{uuid}` | The attestation as Turtle, JSON-LD, N-Triples, N-Quads, or RDF/XML; `202 Accepted` + `Retry-After` while its timestamp is pending |
| `GET /$/provenance/key` | The public key as a `did:key`, multibase, JWK, and PEM, with its key type, cryptosuite, and signer |
| `GET /$/provenance/version/{dataset}` | The persistent and internal data versions |

## Building

```bash
mvn package                      # all three modules, see the table below
scripts/build-whitepaper.sh      # docs/whitepaper/build/whitepaper.pdf (needs TeX Live with latexmk)
```

Releases are made with `scripts/release.sh`. It sets the version, builds and tests, builds the
whitepaper PDF and the vocabulary site, tags, pushes, and creates the GitHub release with the
PDF, the repository zip and the vocabulary site. Because the whitepaper shows output of the demo,
a release has two phases:

```bash
scripts/release.sh prepare 0.13.0                # set 0.13.0 everywhere, commit nothing
scripts/demo.sh --reset                          # then update the whitepaper listings from the run
scripts/release.sh publish 0.13.0 --next 0.14.0  # build, tag, push, release, move to 0.14.0-SNAPSHOT
```

`--dry-run` stops `publish` before anything is committed. Pushing `vocab/` to `main` makes the
GitHub Pages workflow publish the vocabulary at <https://larsw.xyz/jip/>.

| Jar | What it is |
|---|---|
| `jip-fuseki/target/jena-intrinsic-provenance.jar` | The Fuseki module. Jena itself is not bundled; the verifier library, titanium-rdfc (relocated) and BouncyCastle's bcpkix/bcutil are. It uses the bcprov in Fuseki's server jar. |
| `jip-verifier-cli/target/jip-verify.jar` | The offline verifier, self-contained (`java -jar`). |
| `jip-verifier/target/jip-verifier-0.13.0.jar` | The verifier library, for use as a Maven dependency. |

To use the module with your own Fuseki 6.2.0, put `jena-intrinsic-provenance.jar` on the classpath next to
`fuseki-server.jar`. [`docker/entrypoint.sh`](docker/entrypoint.sh) shows the command line.

## Limitations

- Tools that write to the database from another JVM without this module, such as
  `tdb2.tdbloader`, don't advance the version.
- Anyone who can run a query can create attestations, and each attestation is a write to the
  attestation store. Add authentication or rate limiting before real use.
- Without a TSA, timestamps come from the server clock. With one, the TSA vouches for the time
  the attestation was signed, but the times inside the attestation (`prov:startedAtTime` etc.)
  are still the server's. TSA certificates are not checked for revocation.
- Every attestation that is timestamped costs one outgoing HTTP request. In async mode the
  requests run one at a time in the background, so a burst of attestations queues up and stays
  at 202 longer. Public TSAs rate-limit, so use your own or a contracted TSA for real loads.
- The proof is stored as RDF triples, so JSON-LD Verifiable Credential tools may not accept it.
- With the PKCS#11 signer the PIN is in the Fuseki process: the key can't be extracted, but a
  compromised server can still have the token sign. SoftHSM2 in the Docker setup keeps its
  keys in files; use an HSM for real keys.
- A refused attestation (no version, too many rows, inside a write transaction) is reported
  as HTTP 500.

## Layout

```
pom.xml             parent (jena-intrinsic-provenance-parent)
jip-verifier/       verifier library; depends on jena-arq, titanium-rdfc and BouncyCastle
  src/main/java/xyz/larsw/jip/
    canon/    RDFC-1.0 adapter and the result-set encoding
    cert/     AttestationVerifier, Data Integrity proofs (EdDSA, ECDSA), did:key, RFC 3161 tokens, vocabulary terms
jip-verifier-cli/   the offline verifier command (cli/Verify), packaged as jip-verify.jar
jip-fuseki/         the Fuseki module (artifact jena-intrinsic-provenance); uses jip-verifier
  src/main/java/xyz/larsw/jip/
    version/  persistent data version (transaction component, journal recovery, assembler)
    cert/     attestation builder, signers (PKCS#11, local key file), store, TSA client
    service/  the attest SERVICE executor
    function/ jip:dataVersion(), jip:tdbDataVersion()
    fuseki/   Fuseki module, HTTP endpoints, header filter
docker/       Dockerfile, Fuseki configuration, shiro.ini, entrypoint; signer/ (SoftHSM2 + p11-kit server)
docs/         design notes and the whitepaper
vocab/        jip.ttl, the jip: vocabulary (RDFS/OWL)
scripts/      demo, whitepaper build, vocabulary site build, release
.github/      workflow that publishes the vocabulary with GitHub Pages
```
