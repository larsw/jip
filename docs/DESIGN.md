# jena-intrinsic-provenance: design

Proof of concept on **Apache Jena 6.2.0 / Fuseki 6.2.0 (Java 21)** with two goals:

1. Expose a unique, monotonically increasing value that is bumped on every write
   transaction of a TDB2 database.
2. Return a signed, PROV-O-based provenance attestation for the result of a query
   pattern wrapped in a specially named `SERVICE`. The result is bound with RDF
   Dataset Canonicalization (RDFC-1.0, <https://github.com/w3c/rdf-canon>).

Every decision below was agreed in a design review before implementation started.
The custom vocabulary uses the namespace `jip: <https://larsw.xyz/jip/>`. The
namespace is set in one constant so it can be renamed, and `vocab/jip.ttl` describes the terms.

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

## 3. Attestation `SERVICE`

```sparql
SELECT ?name ?email ?attestation WHERE {
  SERVICE <urn:x-provenance:attest> {
    SELECT ?name ?email WHERE { … } ORDER BY ?name LIMIT 10
  }
}
```

- **Scope.** The attestation covers the inner solution sequence. Each executor call
  produces one attestation, so a `SERVICE` on the right-hand side of a join gives
  one attestation per incoming row. Anything the outer query does afterwards is
  outside the attestation.
- **Delivery.** Every output row has the attestation IRI `<urn:uuid:C>` bound to
  `?attestation`. The variable name can be changed with `<urn:x-provenance:attest?var=x>`.
  It is an error if the inner pattern already uses that variable. The variable must
  be projected explicitly, because `SELECT *` does not include it. The signed
  attestation is fetched from `GET /$/provenance/attestation/{uuid}` (Turtle,
  JSON-LD, N-Triples or N-Quads).
- **Empty results.** With `?empty=row`, the default, an empty inner result produces
  one attestation-only row with `jip:solutionCount 0`. With `?empty=none`, an empty
  result gives zero rows and no attestation.
- **No counter.** If the dataset is not a `jip:VersionedDatasetTDB2`, the query fails.
- **Memory cap.** The rows are fully held in memory for hashing. `jip:maxSolutions`
  is a server-level context setting with a default of 10,000. A result above the cap
  fails the query and is never truncated.
- **`SERVICE SILENT`.** On error, the incoming row is returned unchanged, with no
  attestation.

### Turning the result into RDF (input to RDFC-1.0)

The encoding uses the W3C result-set vocabulary (`rs:`
<http://www.w3.org/2001/sw/DataAccess/tests/result-set#>):

```
_:R a rs:ResultSet ; rs:resultVariable "v" (each attested var) ; rs:solution _:S1, … .
_:Si rs:index i            # only when ordered (1-based)
_:Si rs:binding _:B .  _:B rs:variable "v" ; rs:value <term> .   # bound vars only
```

- A blank-node *value* maps to one RDF blank node per distinct label in the result,
  so co-reference between rows is kept.
- The attested variables are the inner pattern's visible variables, minus the
  attestation variable.
- **Ordered** means the inner algebra has `ORDER BY` or `TopN` at the top, below
  slice, distinct, reduced and project.
- **Digest:** `SHA-256(RDFC-1.0 canonical N-Quads)`, as hex.
- **RDF 1.2 terms** (triple terms and literals with a base direction) are rejected.
- **Canonicalization library:** `com.apicatalog:titanium-rdfc:3.0.0`, checked against
  the vendored W3C rdf-canon test suite.

### Attestation (PROV-O, one named graph `<urn:uuid:C>` in the provenance store)

```turtle
<urn:uuid:C> a jip:ResultAttestation, prov:Entity ;
    jip:attests <urn:uuid:C#result> ;
    sec:proof _:proof .
<urn:uuid:C#result> a prov:Entity, jip:SolutionSequence ;
    prov:wasGeneratedBy <urn:uuid:C#exec> ;
    prov:wasDerivedFrom <urn:uuid:DB#vN> ;
    jip:variable "name", "email" ; jip:ordered true ; jip:solutionCount 10 ;
    jip:canonicalization <https://www.w3.org/TR/rdf-canon/> ;
    jip:digestAlgorithm "SHA-256" ; jip:digest "…hex…" .
<urn:uuid:C#exec> a prov:Activity, jip:QueryExecution ;
    prov:used <urn:uuid:DB#vN> ;
    prov:wasAssociatedWith <did:key:zDn…> ;
    prov:startedAtTime … ; prov:endedAtTime … ;
    jip:servicePattern "…inner pattern as SPARQL…" ; jip:queryText "…full query…" .
<urn:uuid:DB#vN> a prov:Entity, jip:DatasetState ;
    prov:specializationOf <datasetIRI or urn:uuid:DB> ; jip:dataVersion N .
<did:key:zDn…> a prov:SoftwareAgent ; rdfs:label "…" .
```

Only the digest of the rows is stored, never the rows themselves.

### Signature: W3C Data Integrity, applied at the RDF level

- **Cryptosuites:** `ecdsa-rdfc-2019` (vc-di-ecdsa) for P-256 and P-384 keys, the default
  through PKCS#11, and `eddsa-rdfc-2022` (vc-di-eddsa) for Ed25519 keys, the local key file.
  The key type selects the cryptosuite and the hash: SHA-256 for Ed25519 and P-256, SHA-384 for
  P-384. The verifier accepts both and checks that the cryptosuite matches the `did:key`'s type.
- **Proof node:** `_:proof a sec:DataIntegrityProof ; sec:cryptosuite "ecdsa-rdfc-2019" ;
  sec:verificationMethod <did:key:zDn…#zDn…> ; sec:proofPurpose sec:assertionMethod ;
  dcterms:created … ; sec:proofValue "z…"`.
- **Unsecured document:** the attestation graph without the proof triples and
  without `<C> sec:proof _:proof`.
- **Proof config:** the proof node triples without `sec:proofValue`.
- **Signature:** over `H(canon(proofConfig)) ‖ H(canon(document))`: Ed25519, or ECDSA with
  SHA-256 / SHA-384 in IEEE P1363 form (`r ‖ s`), encoded as multibase base58btc.
- **Deviation from VC JSON-LD:** the proof is embedded as plain triples, not as a
  JSON-LD `@graph` container. Interoperability with JSON-LD verifiers is best effort.
- **Test:** the vc-di-eddsa test vectors (fixed key, canonical forms, expected
  `proofValue`) and the vc-di-ecdsa `ecdsa-rdfc-2019` vectors for P-256 and P-384 (key pairs,
  canonical forms, hashes; ECDSA signatures are randomized, so the vector signature is verified
  and signing is checked by a round trip with the vector key).

### Timestamps (RFC 3161)

Optional. Added after the design review above; it replaces the earlier "trusted timestamping
is out of scope" risk.

- **What is timestamped.** The TSA's message imprint is `SHA-256(signature)`, where
  `signature` is the raw Ed25519 signature decoded from `sec:proofValue`. The signature covers
  the whole attestation, so the token does too, and the Data Integrity proof is unchanged. This
  is the construction of a CAdES signature time-stamp. It proves the attestation existed at the
  TSA's `genTime`; it does not make the server's own `prov:*Time` values trustworthy.
- **Where the token goes.** After signing, in the same attestation graph:
  ```turtle
  <urn:uuid:C> jip:timestamp _:t .
  _:t a jip:RFC3161Timestamp ;
      jip:timestampToken "…DER TimeStampToken, base64…"^^xsd:base64Binary ;
      jip:timestampAuthority <http://timestamp.digicert.com> ;   # informational
      jip:timestampTime "…"^^xsd:dateTime .                        # informational, = genTime
  ```
  These triples are not part of the signed document. The verifier removes the `jip:timestamp`
  links and the timestamp nodes' triples before checking the proof, so timestamps can be added
  (or several attached) without re-signing. Stripping cannot hide tampering: removing any
  signed triple makes the proof fail.
- **Requests.** SHA-256 imprint, a random 64-bit nonce, `certReq` true (so the token carries the
  TSA certificate and verifies offline). The reply must be granted and match the request
  (imprint, nonce), and the token must verify before it is stored.
- **Priority list and fallback.** `jip:timestampAuthorities` lists TSA URLs in priority order.
  They are tried one at a time, each with `jip:timestampTimeout` (default 5 s); the first valid
  token wins. A TSA that fails is moved to the end of the list for 60 s, so a TSA that is down
  costs one timeout per minute rather than one per attestation. It is still tried if all the
  others fail too.
- **Asynchronous by default.** With `jip:timestampMode async` (the default) the attest
  SERVICE stores the signed attestation and returns; the query never waits for a TSA. In the
  same write transaction the attestation is recorded as pending, as
  `<C> jip:timestampPendingSince "…"` in the store's graph `jip:pendingTimestamps`. One
  background thread per configuration (public TSAs rate-limit) fetches tokens in order. On
  success it adds the timestamp triples to the attestation graph and removes the pending triple,
  again in one transaction, and only if the attestation is still pending, so an attestation
  never gets two tokens. On failure it retries after 5 s, 15 s, 30 s, 1 min, 2 min, 5 min and
  then every 10 min. At server start (`serverAfterStarting`) the pending attestations of an
  earlier run are queued again; if timestamps have been turned off or switched to sync, they
  are released without a timestamp.
- **"Try later".** `GET /$/provenance/attestation/{uuid}` answers a pending attestation with
  `202 Accepted`, `Retry-After` (whole seconds until the next attempt, at least 1; 5 if this
  process isn't retrying it) and `Cache-Control: no-store`, with a JSON body naming the
  attestation, `"status": "timestamp-pending"`, `pendingSince` and `retryAfter`. 202 rather
  than 503: the server is healthy and the resource exists, its processing just isn't complete.
  The `/provenance` SPARQL view is a plain TDB2 service and shows pending attestations already,
  signed but without the timestamp.
- **Synchronous mode.** `jip:timestampMode sync` keeps the original behaviour: the query waits
  for the token before the attestation is stored.
- **Policy.** `jip:timestampPolicy`:
  - `optional` (default). Sync: if no TSA answers, the attestation is issued without a timestamp
    and a warning is logged. Async: retries continue until `jip:timestampMaxWait` (default
    10 min) has passed since the attestation was stored; then it is released without one.
  - `required`. Sync: the attestation fails (HTTP 500, or the incoming row with
    `SERVICE SILENT`). Async: the attestation stays pending and retries never stop, so the
    endpoint keeps answering 202 until a TSA answers.
- **Configuration.** Server `ja:context`, with environment overrides `PROVENANCE_TSA_URLS`,
  `PROVENANCE_TSA_MODE`, `PROVENANCE_TSA_POLICY`, `PROVENANCE_TSA_TIMEOUT` and
  `PROVENANCE_TSA_MAX_WAIT`. A set but empty `PROVENANCE_TSA_URLS`
  turns timestamps off even if the config file names TSAs. Not configured means no timestamps,
  and attestations are exactly as before.
- **Verification.** For each token: the imprint must equal SHA-256 of the proof's signature; the
  CMS signature must verify with the TSA certificate in the token; that certificate must be a
  time-stamping certificate (critical EKU `id-kp-timeStamping` only) valid at `genTime`. Then
  the TSA certificate is chained (PKIX, at `genTime`, no revocation check) to the trust anchors:
  the JVM trust store by default, a PEM file, or not at all. A broken token makes the report
  invalid. An untrusted one is reported but does not, unless a timestamp is required
  (`--require-timestamp`, `Options.requireTimestamp`), which demands at least one valid token
  that is not untrusted.
- **Library.** BouncyCastle (`bcpkix`) for the Time-Stamp Protocol and CMS. The JDK has no
  public API for either.

### Signing key

- **Pluggable.** A `SignerProvider` (found with `ServiceLoader`, chosen by `PROVENANCE_SIGNER`
  / `jip.signer`) opens a `ProvenanceSigner`: a key type, a public key and a `sign(hashData)`.
  Built in: `pkcs11` (default) and `local`.
- **`pkcs11`.** An ECDSA P-256 or P-384 key on a PKCS#11 token, through the JDK's SunPKCS11
  provider: `C_Sign` with `SHA256withECDSAinP1363Format` / `SHA384withECDSAinP1363Format`. The
  private key stays on the token; the module holds only a handle. Settings: the module
  (`PROVENANCE_PKCS11_LIBRARY`), slot index, or a SunPKCS11 config file, the PIN (directly or
  from a file), the key label (`jip-signing`), and optionally `PROVENANCE_PKCS11_GENERATE` to
  create the key pair on the token, with a self-signed certificate, if it is missing.
  SunPKCS11's key store only lists private keys with a certificate of the same `CKA_ID`. On a
  signing failure the module reconnects once (a new SunPKCS11 instance) and retries, so a
  restarted signer process doesn't need a Fuseki restart.
- **Why ECDSA for PKCS#11.** Java 21's SunPKCS11 has no EdDSA support, and EdDSA support in
  tokens varies (SoftHSM2 needs a build with EdDSA enabled; see SoftHSMv2 issue 704). P-256 is
  supported by essentially every token, and `ecdsa-rdfc-2019` is the W3C counterpart of
  `eddsa-rdfc-2022`.
- **Process separation.** With `p11-kit-client.so` as the module, every PKCS#11 call goes over
  a Unix socket to `p11-kit server` in another process, which loads the real module. The Docker
  setup runs that as its own container (`signer`: SoftHSM2 + `p11-kit server`, no network);
  Fuseki and the signer share only the socket volume, and run with the same uid.
- **`local`.** An Ed25519 PKCS#8 PEM. Its path comes from `PROVENANCE_SIGNING_KEY` (env),
  `jip.signingKey` (system property), or the default `$FUSEKI_BASE/provenance/signing-key.pem`.
  If the file is missing, a key is generated once and written with mode 600.
- **Publication.** The key is published as a `did:key` (`zDn…` P-256, `z82…` P-384, `z6Mk…`
  Ed25519), which embeds the public key, so attestations verify offline.
  `GET /$/provenance/key` returns it as a `did:key`, a `publicKeyMultibase`, a JWK and a PEM,
  with its key type, cryptosuite and signer kind.

### Attestation store

- Attestations go into a **separate** TDB2 dataset, one named graph per attestation.
  It must be separate: writing into the queried dataset would bump its counter.
- It is configured at server level with the `ja:context` setting
  `jip:attestationStore`, whose value is the TDB2 location.
- It is exposed read-only as its own Fuseki service (`/provenance`).
- Each attestation costs one write transaction. A per-file store could replace it
  behind the `AttestationStore` interface.

## 4. Verification

Verification lives in the `jip-verifier` library (`AttestationVerifier`), which needs only
`jena-arq` and titanium-rdfc. The CLI `xyz.larsw.jip.cli.Verify`
(module `jip-verifier-cli`, packaged as the self-contained `jip-verify.jar`) parses
arguments, calls the library and prints the report. Together they work as follows:

1. It takes `--results r.srj` (SPARQL JSON), `--attestation c.ttl` and optionally
   `--expect-key did:key:…`, `--tsa-trust system|none|anchors.pem` and `--require-timestamp`.
2. It checks the proof against the `did:key`, over the attestation without its timestamps, and
   then any RFC 3161 timestamps (see "Timestamps" above).
3. It selects the rows whose value is the attestation IRI and rebuilds the `rs:`
   encoding from the attested variables, adding `rs:index` only when the
   attestation says the result is ordered.
4. It canonicalizes, compares the digest, and exits with 0 (ok) or 1 (failure).

`scripts/demo.sh` runs against Docker. It runs an attested query, verifies it
(OK), tampers with the results and verifies again (FAIL), runs an update to show
version v→v+1 and a new attestation, and restarts the container to show the
counter persisted.

## 5. Packaging

- **Build:** a Maven parent with three modules, all `xyz.larsw:*:0.13.0-SNAPSHOT`, all in
  the package `xyz.larsw.jip`:
  - `jip-verifier`: canonicalization, the `rs:` encoding, Data Integrity proofs
    (`DataIntegrityProof`, signing through the `ProofSigner` interface), `did:key`
    (`DidKey`), the attestation vocabulary (`Vocab`, which also holds the namespace), RFC 3161
    tokens (`Rfc3161`, `AttestationTimestamps`) and `AttestationVerifier`. It depends on
    `jena-arq`, titanium-rdfc and BouncyCastle (`bcpkix`).
  - `jip-verifier-cli`: the `Verify` command, shaded with all its dependencies into
    `jip-verify.jar`.
  - `jena-intrinsic-provenance` (directory `jip-fuseki`): the data version, the attest
    SERVICE, the attestation store, the signers (`Pkcs11Signer`, `SigningKey`), the TSA client
    (`TimestampAuthorities`) and the Fuseki module. Jena is `provided`; `jip-verifier`,
    titanium-rdfc, `bcpkix` and `bcutil` are shaded into the jar, so Fuseki still loads one jar.
- **Registration:** a `JenaSubsystemLifecycle` registers the assembler, the
  functions and the service executor. A `FusekiAutoModule` adds the `/$/provenance/*`
  servlets and the header filter.
- **Docker:** a multi-stage build (`maven:3.9-eclipse-temurin-21` → `eclipse-temurin:21-jre`).
  `jena-fuseki-server-6.2.0.jar` is downloaded from Maven Central and checked
  against a pinned SHA-256. The container runs as a non-root user, with one
  `/fuseki` volume and port 3030. The build stage installs SoftHSM2 so the PKCS#11 tests run on
  a real token; the runtime image adds `p11-kit-client.so`. A second image, `docker/signer`
  (Ubuntu 24.04, SoftHSM2, `p11-kit server`), holds the token; Compose connects the two through
  a socket volume and gives the signer no network.

## 6. Accepted risks

- Anyone who can query can create attestations, and each one is a write to the
  provenance store. That can be abused to make the server do a lot of writes.
- The times inside an attestation come from the server clock. An RFC 3161 timestamp, when
  configured, proves when the attestation was signed, but not those values. TSA certificates
  are not checked for revocation.
- A timestamped attestation costs one outgoing HTTP request, and public TSAs rate-limit. In
  async mode the requests run on one background thread, so a burst of attestations queues up
  and their 202 phase gets longer; in sync mode the request runs while the query waits.
- If one request touches several versioned datasets, the headers report the last
  one that was observed.
- The PKCS#11 PIN is in the Fuseki process. The key can't be extracted, but a compromised
  Fuseki process can still have the token sign anything. The p11-kit client/server forwarding is
  Linux-only, and SoftHSM2 stores keys in files: it stands in for an HSM.

## 7. Implementation notes

These are the places where building the PoC refined the plan above.

- **Finding the component.** ARQ evaluates against TDB2's storage object (`DatasetGraphTDB`),
  not the switchable container, and that storage object gets a new `Context` on compaction.
  So the component is looked up through the coordinator's `listExternals()`, which survives
  compaction, rather than only through the dataset context.
- **`jip:dataVersion()` outside a transaction.** TDB2 autocommits each access, so there is no
  single snapshot, and the function returns the last committed version. The attest SERVICE
  instead opens its own read transaction, so its version and its data always match.
- **TDB2 outside a transaction (embedded use).** In Jena 6.2.0, lazily evaluated patterns fail
  outside a transaction even without this module. Embedded callers must use
  `Txn.executeRead`; Fuseki always does.
- **Error status.** A refused attestation (unversioned dataset, cap exceeded, write
  transaction) reaches the client as HTTP 500, because Fuseki maps execution-time exceptions
  to 500.
- **Docker security.** In UI mode Fuseki writes a `shiro.ini` that limits `/$/**` to localhost.
  The image installs one that additionally opens `/$/provenance/**` (read-only) to everyone.
- **Recorded pattern text.** `jip:servicePattern` is written after undoing the algebra's scope
  renaming (`?/p` → `?p`), so it reads like the query.
- **Measured cost.** Digesting 10,000 rows takes about 1 s, well inside the 10 s
  canonicalization limit, which also stops the W3C poison-graph test case.
- **Packaging.** In the Fuseki module jar, titanium-rdfc is shaded **and relocated**,
  because the Fuseki jar already bundles other versions of `com.apicatalog.rdf.*`. The
  verifier library declares it as an ordinary dependency and leaves shading to whoever
  embeds it.
- **BouncyCastle.** `jena-fuseki-server-6.2.0.jar` bundles `bcprov` 1.84 unrelocated (through
  Shiro), but not `bcpkix`/`bcutil`. The module jar shades those two, also unrelocated, at the
  same version (`ver.bouncycastle`), so they link against Fuseki's `bcprov`; none of their
  classes overlap with the server jar. Keep the version in step when moving to another Fuseki.
  BouncyCastle is used only through its lightweight API; no JCE provider is registered. Besides
  the Time-Stamp Protocol it handles the Ed25519 key encodings (PKCS#8, SubjectPublicKeyInfo,
  PEM) and derives the public key from the seed; signing and verifying stay on the JDK's Ed25519.
  Base58 and the multicodec prefixes of `did:key` remain hand-written: BouncyCastle has neither.
