# jena-intrinsic-provenance

A proof of concept for **Apache Jena 6.2.0 / Fuseki 6.2.0** (Java 21). It answers two questions:

1. **Can TDB2 expose a unique, monotonically increasing value that is bumped on every write
   transaction?** TDB2 has such a value, but it lives only in memory. This module adds a
   persistent one that is journaled together with the data ([findings](#1-a-write-counter-for-tdb2)).
2. **Can a query get a signed, PROV-O provenance certificate that binds its result?** Yes. Wrap
   the pattern in `SERVICE <urn:x-provenance:certify>`, and the rows are hashed with
   [RDFC-1.0](https://www.w3.org/TR/rdf-canon/) and signed as a W3C Data Integrity
   `eddsa-rdfc-2022` proof ([details](#2-certified-query-results)).

The design was agreed before implementation and is recorded in [docs/DESIGN.md](docs/DESIGN.md).

## Quick start

```bash
docker compose up -d --build     # builds the module, runs all tests on JDK 21, starts Fuseki on :3030
scripts/demo.sh --reset          # end-to-end demo (needs curl and jq); --reset wipes the demo volume
```

The demo works through these steps:

1. Load data.
2. Run a certified query.
3. Fetch the certificate.
4. Verify it in a separate container.
5. Tamper with the results, and see verification fail.
6. Run an update, which gives a new version and a new certificate.
7. Certify an empty result.
8. Compare the persistent counter with TDB2's internal one.
9. Restart the container: the persistent counter carries on and TDB2's starts again from 0.
10. Query all certificates as PROV-O.

```sparql
PREFIX ex: <http://example.org/>
SELECT ?name ?email ?cert WHERE {
  SERVICE <urn:x-provenance:certify> {
    SELECT ?name ?email WHERE { ?p ex:name ?name OPTIONAL { ?p ex:email ?email } } ORDER BY ?name
  }
}
```

Every row comes back with `?cert` = `<urn:uuid:…>`. Fetch the certificate from
`GET /$/provenance/certificate/{uuid}`, then verify it independently:

```bash
docker run --rm -v "$PWD/demo-out:/data:ro" jena-intrinsic-provenance:0.1.0 \
  verify --results /data/results.srj --cert /data/certificate.ttl --expect-key did:key:z6Mk…
```

---

## 1. A write counter for TDB2

### What TDB2 already has

These findings come from reading the 6.2.0 sources (`jena-dboe-transaction`, `jena-tdb2`,
`jena-fuseki-main`):

| Finding | Source |
|---|---|
| `TransactionCoordinator` keeps `AtomicLong dataVersion`. It goes up by 1 in `advanceDataVersion()` inside the commit critical section for every committed write transaction. Aborts and reads never move it. | `dboe/transaction/txn/TransactionCoordinator.java` |
| Each transaction records the version it started from, and `Transaction.getDataVersion()` (`TransactionInfo`) is public. Inside a transaction you can read it with `DatasetGraphTDB.getTxnSystem().getTransactionInfo()`. | `Transaction.java`, `TransactionalBase.java` |
| It is **memory only**. The coordinator starts it at 0 on every JVM start. Compaction carries it over (`takeOverFrom`). | `TransactionCoordinator`, `tdb2/sys/DatabaseOps.compact` |
| No other value changes exactly once per commit. The journal is truncated after every commit (`journal.truncate(0)`). Index and node-table state only change when data changes, so they can't count empty write transactions, and compaction rewrites them. | `TransactionCoordinator.executeCommitWriter`, `DatabaseOps.compact` |

So the internal counter is monotonic and bumped on every write, but it **isn't unique over time**.
After a restart, "version 5" refers to a different state than before. It is still exposed, as
`jip:tdbDataVersion()`, and used as a cross-check.

### What this module adds: a persistent, journaled counter

DBOE lets subsystems add their own `TransactionalComponent` to TDB2's coordinator. jena-text uses
the same `addExternal` hook. `DataVersionComponent` is such a component, with id `0x50524F56`
("PROV"); TDB2's own components use ids 1–51.

- **Atomic with the data.** On commit, the component writes a REDO record `(format, version+1)`
  into TDB2's journal, under the same COMMIT record as the data. After the commit point it
  rewrites `jip-data-version.properties` in the database root (temp file, fsync, rename).
  `_begin`, `_commit` and `_commitEnd` all run inside the coordinator's lock, so every
  transaction sees a version that matches its data snapshot.
- **What bumps it.** Every committed write transaction, including ones that change nothing.
  Within one process, `persistent − internal` therefore stays constant, and a test checks this.
- **Survives restart and compaction.** Externals move to the new coordinator when the database
  is compacted, and the state file sits outside `Data-NNNN/`.
- **Crash-safe.** TDB2 replays its journal when the database opens, and silently drops entries
  for components that aren't registered yet. Fuseki opens config-file datasets in `parseConfig`,
  before any `FusekiModule` hook runs. That leaves exactly one place to hook in: an
  **assembler**. `jip:VersionedDatasetTDB2` replays our committed journal entries
  (`PreOpenJournalRecovery`) *before* TDB2 opens the database, then attaches the component and
  returns the plain TDB2 dataset. Compaction, backup and stats keep working.
- **Identity.** A UUID is minted with the state file. A dataset state is `<urn:uuid:DB#vN>`,
  `prov:specializationOf` the optional `jip:datasetIRI`. Rebuilding from a backup gives a new
  UUID, so (uuid, version) never collides.

Other approaches I considered and rejected:

| Option | Why not |
|---|---|
| Expose `dataVersion` as is | Restarts at 0, so it isn't unique over time. |
| Store the counter in TDB2's prefix table | Atomic, but a hack: a listener is needed to write it, listeners don't survive compaction, and it could leak into the dataset's prefixes. |
| Wrap the dataset and count commits in a separate file | Not atomic with the data; a crash can split them. |
| Auto-attach from a Fuseki module | No assembler config needed, but it can't take part in journal recovery, which leaves a crash window. |

### Exposure

| How | What |
|---|---|
| `jip:dataVersion()` | Persistent version of the snapshot the query reads. Outside a transaction, the last committed version. |
| `jip:tdbDataVersion()` | TDB2's internal, volatile counter, for comparison. |
| `GET /$/provenance/version/{dataset}` | `{"datasetId","datasetIRI","version","tdbInternal","persistent"}`, both values from one read transaction. |
| `X-Dataset-Version`, `X-Dataset-Id` headers | On reads, the snapshot the response was computed from. On writes, the version the request committed. Omitted for aborted writes and unversioned datasets. |

The headers are exact. The component records the version on the request thread when a transaction
begins or commits. A servlet filter sets the headers just before the first body byte is written.
Fuseki starts its read transaction before it writes results, so there's no off-by-one. There is no
`ETag`: queries using `NOW()`/`RAND()` would make it a wrong validator.

### Known gaps

- **Offline writers skip the counter.** For example `tdb2.tdbloader` running in another JVM
  without this module.
- **Byte-for-byte copies share an identity.** If you copy a database directory and then write to
  both copies, they share a UUID and their histories diverge.

---

## 2. Certified query results

### Semantics

- **What is covered.** The certificate covers the **inner solution sequence** of one `SERVICE`
  call. To certify a whole query, put it inside as a sub-SELECT. If the `SERVICE` sits on the
  right-hand side of a join, it runs once per incoming row, and each call gets its own certificate.
- **Snapshot.** The inner pattern is evaluated, and the persistent version read, in the same read
  transaction: the query's own, or a new one if there is none. Running inside a write transaction
  is refused, because uncommitted changes have no version.
- **Variable.** `?cert` is bound on every row. Rename it with
  `<urn:x-provenance:certify?var=prov>`. `SELECT *` does not include it, so project it explicitly.
- **Empty results.** By default an empty result gives one certificate-only row with
  `jip:solutionCount 0`, which proves absence. Use `?empty=none` for zero rows and no certificate.
- **Size limit.** `jip:maxSolutions` (server context, default 10,000). Results above it fail the
  query and are never truncated.
- **Unversioned datasets fail.** The query fails with HTTP 500, since Fuseki maps
  execution-time errors to 500. With `SERVICE SILENT`, the incoming row is passed through
  without a certificate.

### Binding the result: RDFC-1.0

- **Encoding.** A solution sequence isn't RDF, so it is encoded with the W3C result-set vocabulary
  (`rs:solution`, `rs:binding`, `rs:variable`, `rs:value`). Each solution and each binding is a
  blank node, so duplicate rows are counted.
- **Canonicalization and digest.** The encoding is canonicalized with **RDFC-1.0**
  ([titanium-rdfc](https://github.com/filip26/titanium-rdfc) 3.0.0, shaded and relocated) and
  hashed with SHA-256.
- **Order** (`rs:index`) is included only when the inner pattern is ordered (`ORDER BY` or
  `TopN`). Without `ORDER BY`, TDB2's row order is an accident of node ids, and compaction
  changes it.
- **Blank-node values.** Labels don't affect the digest, but co-reference between rows does.
- **RDF 1.2 terms** (triple terms, and literals with a base direction) are rejected. RDFC-1.0
  only defines RDF 1.1.

### The certificate

The certificate is stored as a named graph in a separate TDB2 dataset (`/provenance`, read-only
over HTTP). It is a separate dataset because writing certificates into the queried one would bump
its counter.

```turtle
<urn:uuid:C> a jip:ResultCertificate, prov:Entity ;
    jip:certifies <urn:uuid:C#result> ;
    sec:proof [ a sec:DataIntegrityProof ; sec:cryptosuite "eddsa-rdfc-2022"^^sec:cryptosuiteString ;
                sec:verificationMethod <did:key:z6Mk…#z6Mk…> ; sec:proofPurpose sec:assertionMethod ;
                dcterms:created "…"^^xsd:dateTime ; sec:proofValue "z…"^^sec:multibase ] .
<urn:uuid:C#result> a prov:Entity, jip:SolutionSequence ;
    prov:wasGeneratedBy <urn:uuid:C#exec> ;  prov:wasDerivedFrom <urn:uuid:DB#v1> ;
    jip:variable "email", "name" ; jip:ordered true ; jip:solutionCount 3 ;
    jip:canonicalization <https://www.w3.org/TR/rdf-canon/> ; jip:digestAlgorithm "SHA-256" ; jip:digest "feb2…" .
<urn:uuid:C#exec> a prov:Activity, jip:QueryExecution ;
    prov:used <urn:uuid:DB#v1> ; prov:wasAssociatedWith <did:key:z6Mk…> ;
    prov:startedAtTime … ; prov:endedAtTime … ; jip:servicePattern "…" ; jip:queryText "…" .
<urn:uuid:DB#v1> a prov:Entity, jip:DatasetState ; jip:dataVersion 1 ;
    prov:specializationOf <https://example.org/datasets/ds> .
<did:key:z6Mk…> a prov:SoftwareAgent ; rdfs:label "jena-intrinsic-provenance … on Apache Jena 6.2.0" .
```

Only the digest is stored, never the rows. `jip:` is a placeholder namespace
(`http://example.org/jip#`, defined in `JIP.NS`).

**Signature.** The W3C Data Integrity cryptosuite **`eddsa-rdfc-2022`**, applied at the RDF
level:
- The signature covers `SHA-256(RDFC(proof options)) ‖ SHA-256(RDFC(certificate without proof))`,
  signed with Ed25519 and encoded as multibase base58btc.
- The key is a `did:key`, so certificates verify offline.
- The proof options canonicalize **byte for byte** like the spec's JSON-LD expansion, and the
  vc-di-eddsa test vector's `proofValue` is reproduced exactly.
- One deviation: the proof is embedded as plain triples, not inside a JSON-LD `@graph` container.
  Interoperability with off-the-shelf JSON-LD verifiers is best effort.

**Key.** An Ed25519 PKCS#8 PEM, taken from `PROVENANCE_SIGNING_KEY` or `-Djip.signingKey`. If
neither is set, it is generated once at `$FUSEKI_BASE/provenance/signing-key.pem` with mode 600.
It is published at `GET /$/provenance/key` as a `did:key`, multibase, JWK and PEM.

### Verifying

`org.example.jena.provenance.cli.Verify` is a CLI; in Docker, run it as `docker run … verify`.
It doesn't trust the server and works as follows:

1. Checks the proof against the `did:key` (optionally pinned with `--expect-key`).
2. Picks the rows that carry the certificate IRI.
3. Rebuilds the `rs:` encoding from the certified variables, adding `rs:index` only if the
   certificate says the result is ordered.
4. Canonicalizes it and compares the digest.

It exits with 0 (valid), 1 (invalid) or 2 (error). The outer query must project every certified
variable unchanged; anything the outer query adds (filtering, joins, re-sorting) is outside the
certificate.

---

## Configuration reference

The configuration lives in `docker/config.ttl`:

```turtle
[] a fuseki:Server ;
   ja:context [ ja:cxtName "http://example.org/jip#certificateStore" ; ja:cxtValue "/fuseki/databases/provenance" ] ;
   ja:context [ ja:cxtName "http://example.org/jip#maxSolutions"    ; ja:cxtValue "10000" ] .

:dataset a jip:VersionedDatasetTDB2 ;              # instead of tdb2:DatasetTDB2
    tdb2:location "/fuseki/databases/ds" ;
    jip:datasetIRI <https://example.org/datasets/ds> .   # optional
```

| Endpoint | |
|---|---|
| `GET /$/provenance/certificate/{uuid}` | Turtle, JSON-LD, N-Triples, N-Quads or RDF/XML, by `Accept` or `?format=` |
| `GET /$/provenance/key` | Signing key |
| `GET /$/provenance/version/{dataset}` | Data versions |

In UI mode Fuseki restricts `/$/**` to localhost. The image ships a `shiro.ini` that makes only
`/$/provenance/**` public.

How the pieces get loaded:
- **Jena:** `InitJIP` (`JenaSubsystemLifecycle`) registers the assembler, the functions and the
  `SERVICE` executor.
- **Fuseki:** `ProvenanceFusekiModule` (`FusekiAutoModule`) adds the endpoints and the header
  filter. Put the jar on Fuseki's classpath and it loads automatically.

## Tests and measurements

`mvn test` runs 99 tests, and the Docker build runs them again on JDK 21:

- **W3C rdf-canon suite:** all 65 tests pass through the Jena adapter, including the blank-node
  mapping tests, SHA-384, N-Quads escaping and the poison-clique negative test. It is vendored
  under `src/test/resources/w3c` with its licence and source commit.
- **vc-di-eddsa `eddsa-rdfc-2022` test vectors:** the key, the hashes, the canonical proof
  configuration and the signature all match exactly.
- **Data version:**
  - bump semantics and snapshot isolation under concurrent readers
  - restart persistence and `persistent − internal` staying constant
  - compaction to `Data-0002`
  - journal replay of a committed entry, skipping an uncommitted one
- **Certify `SERVICE`:**
  - verification round trip, ordered and unordered results, tamper and dropped-row detection
  - empty-result modes, variable naming and conflicts, the cap
  - unversioned and `SILENT` handling, the write-transaction refusal
  - correlated calls, and the version advancing after an update
- **Fuseki end-to-end over HTTP**, using `docker/config.ttl`.

Digest time at the 10,000-row cap (two variables, measured on the development machine; the
canonicalization time limit is 10 s):

| Result | Digest time |
|---|---|
| Unordered | about 1.1 s |
| Ordered | about 0.7 s |
| 10 distinct rows repeated 1,000 times | about 0.9 s |

## Limitations and risks

- **Abuse.** Anyone who can query can create certificates, and each one is a write transaction on
  the certificate store. That can be used to make the server do a lot of writes. Put
  authentication in front of it, or rate-limit it, before real use.
- **Timestamps** come from the server clock. Trusted timestamping (RFC 3161) is not done.
- **TDB2 outside a transaction (embedded use, not Fuseki).** In Jena 6.2.0, lazily evaluated
  patterns fail outside a transaction. Wrap embedded queries in `Txn.executeRead`; Fuseki always
  does this.
- **Jena's IRI checker** warns about the `#` in `did:key:…#…` verification methods. DID URLs
  allow it, and the CLI parser silences that warning.
- **Several versioned datasets in one request:** the headers report the last one observed.

## Layout

```
docs/DESIGN.md                      agreed design + implementation notes
src/main/java/org/example/jena/provenance/
  version/   DataVersionComponent, PreOpenJournalRecovery, VersionedDatasetAssembler, DataVersion, RequestVersionTracker
  canon/     RdfCanonicalizer (titanium-rdfc adapter), ResultSetEncoding (rs:)
  cert/      CertificateBuilder, DataIntegrityProof, SigningKey, CertificateStore, CertificateVerifier
  service/   CertifyServiceExecutor, CertifyRequest
  function/  jip:dataVersion(), jip:tdbDataVersion()
  fuseki/    ProvenanceFusekiModule, ProvenanceServlet, DataVersionHeaderFilter
  cli/       Verify
docker/      Dockerfile, config.ttl, shiro.ini, entrypoint.sh
scripts/demo.sh
```

The coordinates `org.example.jena:jena-intrinsic-provenance` and the `jip:` namespace are
placeholders.
