# jena-intrinsic-provenance: design

Proof of concept on **Apache Jena 6.2.0 / Fuseki 6.2.0 (Java 21)** with two goals:

1. Expose a unique, monotonically increasing value that is bumped on every write
   transaction of a TDB2 database.
2. Return a signed, PROV-O-based provenance certificate for the result of a query
   pattern wrapped in a specially named `SERVICE`. The result is bound with RDF
   Dataset Canonicalization (RDFC-1.0, <https://github.com/w3c/rdf-canon>).

Every decision below was agreed in a design review before implementation started.
The custom vocabulary uses the placeholder namespace `jip: <http://example.org/jip#>`,
which is defined in one constant so it can be renamed.

## 1. Background: what TDB2 already has

These findings come from the 6.2.0 sources:

| Fact | Where |
|---|---|
| `TransactionCoordinator` keeps `AtomicLong dataVersion`. It is incremented once per committed write transaction, inside the commit critical section, and never moves on aborts or reads. | `dboe/transaction/txn/TransactionCoordinator.java` (`advanceDataVersion`) |
| Every transaction records the version it started at. `Transaction.getDataVersion()` is public. | `Transaction.java` |
| The counter is **in memory only** and starts again at 0 on every JVM start. Compaction carries it over (`takeOverFrom`). | `TransactionCoordinator`, `tdb2/sys/DatabaseOps.java` (`compact`) |
| Custom `TransactionalComponent`s can be added after start with `modifyConfig` + `addExternal`. Externals are moved to the new coordinator on compaction. | `TransactionCoordinator.addExternal`, `DatabaseOps.compact` |
| Component REDO data goes into TDB2's journal under the same COMMIT record as the data. | `TransactionCoordinator.executeCommitWriter` |
| Journal recovery runs when the database **opens**. Entries for components that are not registered yet are dropped with a warning. | `TransactionCoordinator.recovery` |
| Fuseki assembles config-file datasets in `parseConfig`, which runs **before** any `FusekiModule` hook. | `fuseki/main/FusekiServer.java` (`build`) |
| TDB2 component ids are 4-byte ints in the range 1–51. | `tdb2/sys/ComponentIdMgr.java` |
| A custom `ChainingServiceExecutor` runs before the `httpServiceAllowed` check. | `sparql/service/*`, `sparql/exec/http/Service.java` |
| Jena 6.2.0 has no RDFC-1.0 implementation. | — |

## 2. Persistent data version

- **Mechanism.** A `TransactionalComponentExternal` with component id `0x50524F56` ("PROV")
  is registered on the TDB2 coordinator. Its REDO entry (format int + version long)
  is journaled atomically with the data. After the commit point, `_commit` writes
  the state file with an atomic temp-file write, fsync and rename. `_commitEnd`
  publishes the new value in memory.
- **What bumps it.** Every committed write transaction, including ones that change
  nothing. Aborts and reads never bump it. This matches TDB2's own `dataVersion`,
  so within one process `persistent − internal` stays constant.
- **Durability.** The counter is monotonic across restarts and compactions. The
  component instance moves to the new coordinator on compaction.
- **Attaching it (assembler only).** The type is `jip:VersionedDatasetTDB2` with
  `tdb2:location` (required), `tdb2:unionDefaultGraph` (optional) and
  `jip:datasetIRI` (optional). Before TDB2 opens the database, the assembler reads
  `Data-NNNN/journal.jrnl` and applies any committed REDO entries for our component
  to the state file. This closes the crash window between the commit point and the
  state-file write. The assembler then delegates to `DatasetAssemblerTDB2.make` and
  attaches the component. It returns the **unwrapped** TDB2 dataset, so compaction,
  backup and stats still work.
- **Identity.** A random UUID is minted when the state file is created and stored
  alongside the counter. A dataset state is `<urn:uuid:DB#vN>`, and it is
  `prov:specializationOf` the configured `jip:datasetIRI`, or `<urn:uuid:DB>`.
  The pair (uuid, version) is unique. A rebuild or restore gets a new UUID.
- **`--mem--` locations** are supported for tests. The counter is held in memory there.
- **Known gaps (documented, not solved).**
  - Offline writers that don't load this module (for example `tdb2.tdbloader` in
    another JVM) skip the counter.
  - Copying a database directory byte for byte and writing to both copies breaks
    uniqueness.

### Exposure

- `jip:dataVersion()`: the persistent version of the snapshot the current query reads.
- `jip:tdbDataVersion()`: TDB2's internal, volatile `dataVersion`, for comparison.
- `GET /$/provenance/version/{dataset}` →
  `{"datasetId":"urn:uuid:…","version":N,"tdbInternal":M}`.
- `X-Dataset-Version` / `X-Dataset-Id` response headers. These are exact:
  - The component records the version in a thread-local when a transaction begins
    (reads), or when it commits (writes, recorded in `_commitEnd`).
  - A servlet filter sets the headers when the body stream is first requested, or
    after the chain completes if nothing has been committed yet.
  - An aborted write, or a request that never touches a versioned dataset, gets no
    headers.
  - There is no `ETag`, because queries with `NOW()`/`RAND()` would make it a wrong
    validator.
- Using any of these on a dataset without the component is an error.

## 3. Certificate `SERVICE`

```sparql
SELECT ?name ?email ?cert WHERE {
  SERVICE <urn:x-provenance:certify> {
    SELECT ?name ?email WHERE { … } ORDER BY ?name LIMIT 10
  }
}
```

- **Scope.** The certificate covers the inner solution sequence. Each executor call
  produces one certificate, so a `SERVICE` on the right-hand side of a join gives
  one certificate per incoming row. Anything the outer query does afterwards is
  outside the certificate.
- **Delivery.** Every output row has the certificate IRI `<urn:uuid:C>` bound to
  `?cert`. The variable name can be changed with `<urn:x-provenance:certify?var=x>`.
  It is an error if the inner pattern already uses that variable. The variable must
  be projected explicitly, because `SELECT *` does not include it. The signed
  certificate is fetched from `GET /$/provenance/certificate/{uuid}` (Turtle,
  JSON-LD, N-Triples or N-Quads).
- **Empty results.** With `?empty=row`, the default, an empty inner result produces
  one certificate-only row with `jip:solutionCount 0`. With `?empty=none`, an empty
  result gives zero rows and no certificate.
- **No counter.** If the dataset is not a `jip:VersionedDatasetTDB2`, the query fails.
- **Memory cap.** The rows are fully held in memory for hashing. `jip:maxSolutions`
  is a server-level context setting with a default of 10,000. A result above the cap
  fails the query and is never truncated.
- **`SERVICE SILENT`.** On error, the incoming row is returned unchanged, with no
  certificate.

### Turning the result into RDF (input to RDFC-1.0)

The encoding uses the W3C result-set vocabulary (`rs:`
<http://www.w3.org/2001/sw/DataAccess/tests/result-set#>):

```
_:R a rs:ResultSet ; rs:resultVariable "v" (each certified var) ; rs:solution _:S1, … .
_:Si rs:index i            # only when ordered (1-based)
_:Si rs:binding _:B .  _:B rs:variable "v" ; rs:value <term> .   # bound vars only
```

- A blank-node *value* maps to one RDF blank node per distinct label in the result,
  so co-reference between rows is kept.
- The certified variables are the inner pattern's visible variables, minus the
  certificate variable.
- **Ordered** means the inner algebra has `ORDER BY` or `TopN` at the top, below
  slice, distinct, reduced and project.
- **Digest:** `SHA-256(RDFC-1.0 canonical N-Quads)`, as hex.
- **RDF 1.2 terms** (triple terms and literals with a base direction) are rejected.
- **Canonicalization library:** `com.apicatalog:titanium-rdfc:3.0.0`, checked against
  the vendored W3C rdf-canon test suite.

### Certificate (PROV-O, one named graph `<urn:uuid:C>` in the provenance store)

```turtle
<urn:uuid:C> a jip:ResultCertificate, prov:Entity ;
    jip:certifies <urn:uuid:C#result> ;
    sec:proof _:proof .
<urn:uuid:C#result> a prov:Entity, jip:SolutionSequence ;
    prov:wasGeneratedBy <urn:uuid:C#exec> ;
    prov:wasDerivedFrom <urn:uuid:DB#vN> ;
    jip:variable "name", "email" ; jip:ordered true ; jip:solutionCount 10 ;
    jip:canonicalization <https://www.w3.org/TR/rdf-canon/> ;
    jip:digestAlgorithm "SHA-256" ; jip:digest "…hex…" .
<urn:uuid:C#exec> a prov:Activity, jip:QueryExecution ;
    prov:used <urn:uuid:DB#vN> ;
    prov:wasAssociatedWith <did:key:z6Mk…> ;
    prov:startedAtTime … ; prov:endedAtTime … ;
    jip:servicePattern "…inner pattern as SPARQL…" ; jip:queryText "…full query…" .
<urn:uuid:DB#vN> a prov:Entity, jip:DatasetState ;
    prov:specializationOf <datasetIRI or urn:uuid:DB> ; jip:dataVersion N .
<did:key:z6Mk…> a prov:SoftwareAgent ; rdfs:label "…" .
```

Only the digest of the rows is stored, never the rows themselves.

### Signature: W3C Data Integrity `eddsa-rdfc-2022`, applied at the RDF level

- **Proof node:** `_:proof a sec:DataIntegrityProof ; sec:cryptosuite "eddsa-rdfc-2022" ;
  sec:verificationMethod <did:key:z6Mk…#z6Mk…> ; sec:proofPurpose sec:assertionMethod ;
  dcterms:created … ; sec:proofValue "z…"`.
- **Unsecured document:** the certificate graph without the proof triples and
  without `<C> sec:proof _:proof`.
- **Proof config:** the proof node triples without `sec:proofValue`.
- **Signature:** `Ed25519(SHA-256(canon(proofConfig)) ‖ SHA-256(canon(document)))`,
  encoded as multibase base58btc.
- **Deviation from VC JSON-LD:** the proof is embedded as plain triples, not as a
  JSON-LD `@graph` container. Interoperability with JSON-LD verifiers is best effort.
- **Test:** the vc-di-eddsa test vectors (fixed key, canonical forms, expected
  `proofValue`).

### Signing key

- The key is an Ed25519 PKCS#8 PEM. Its path comes from `PROVENANCE_SIGNING_KEY`
  (env), `jip.signingKey` (system property), or the default
  `$FUSEKI_BASE/provenance/signing-key.pem`.
- If the file is missing, a key is generated once and written with mode 600.
- It is published as a `did:key`, which embeds the public key, so certificates
  verify offline. `GET /$/provenance/key` returns it as a `did:key`, a
  `publicKeyMultibase`, a JWK and a PEM.

### Certificate store

- Certificates go into a **separate** TDB2 dataset, one named graph per certificate.
  It must be separate: writing into the queried dataset would bump its counter.
- It is configured at server level with the `ja:context` setting
  `jip:certificateStore`, whose value is the TDB2 location.
- It is exposed read-only as its own Fuseki service (`/provenance`).
- Each certificate costs one write transaction. A per-file store could replace it
  behind the `CertificateStore` interface.

## 4. Verification

The CLI `org.example.jena.provenance.cli.Verify` works as follows:

1. It takes `--results r.srj` (SPARQL JSON), `--cert c.ttl` and optionally
   `--expect-key did:key:…`.
2. It checks the proof against the `did:key`.
3. It selects the rows whose value is the certificate IRI and rebuilds the `rs:`
   encoding from the certified variables, adding `rs:index` only when the
   certificate says the result is ordered.
4. It canonicalizes, compares the digest, and exits with 0 (ok) or 1 (failure).

`scripts/demo.sh` runs against Docker. It runs a certified query, verifies it
(OK), tampers with the results and verifies again (FAIL), runs an update to show
version v→v+1 and a new certificate, and restarts the container to show the
counter persisted.

## 5. Packaging

- **Build:** one Maven module, `org.example.jena:jena-intrinsic-provenance:0.1.0-SNAPSHOT`,
  package `org.example.jena.provenance`. Jena is `provided`, and titanium-rdfc is
  shaded into the jar.
- **Registration:** a `JenaSubsystemLifecycle` registers the assembler, the
  functions and the service executor. A `FusekiAutoModule` adds the `/$/provenance/*`
  servlets and the header filter.
- **Docker:** a multi-stage build (`maven:3.9-eclipse-temurin-21` → `eclipse-temurin:21-jre`).
  `jena-fuseki-server-6.2.0.jar` is downloaded from Maven Central and checked
  against a pinned SHA-256. The container runs as a non-root user, with one
  `/fuseki` volume and port 3030.

## 6. Accepted risks

- Anyone who can query can create certificates, and each one is a write to the
  provenance store. That can be abused to make the server do a lot of writes.
- Timestamps come from the server clock. Trusted timestamping (RFC 3161) is out
  of scope.
- If one request touches several versioned datasets, the headers report the last
  one that was observed.
