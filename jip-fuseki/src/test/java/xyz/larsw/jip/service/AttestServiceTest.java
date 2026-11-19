package xyz.larsw.jip.service;

import static org.junit.jupiter.api.Assertions.*;

import java.net.ServerSocket;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.jena.graph.Graph;
import org.apache.jena.graph.Node;
import org.apache.jena.graph.NodeFactory;
import org.apache.jena.query.QueryExecException;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFParser;
import org.apache.jena.sparql.core.DatasetGraph;
import org.apache.jena.sparql.core.Var;
import org.apache.jena.sparql.engine.binding.Binding;
import org.apache.jena.sparql.engine.binding.BindingBuilder;
import org.apache.jena.sparql.exec.QueryExec;
import org.apache.jena.sparql.exec.RowSet;
import org.apache.jena.sparql.exec.UpdateExec;
import org.apache.jena.system.Txn;
import org.apache.jena.tdb2.DatabaseMgr;
import org.apache.jena.tdb2.sys.TDBInternal;
import xyz.larsw.jip.JIP;
import xyz.larsw.jip.attestation.AttestationStore;
import xyz.larsw.jip.attestation.AttestationVerifier;
import xyz.larsw.jip.attestation.GatedTsa;
import xyz.larsw.jip.attestation.ProvenanceKeys;
import xyz.larsw.jip.attestation.Rfc3161;
import xyz.larsw.jip.attestation.SigningKey;
import xyz.larsw.jip.attestation.TestTsa;
import xyz.larsw.jip.attestation.TimestampAuthorities;
import xyz.larsw.jip.attestation.Vocab;
import xyz.larsw.jip.version.DataVersion;
import xyz.larsw.jip.TestLib;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AttestServiceTest {

    static final String PREFIXES = """
            PREFIX ex:  <http://example.org/>
            PREFIX jip: <https://larsw.xyz/jip/>
            """;
    static final String DATA = """
            PREFIX ex: <http://example.org/>
            ex:alice ex:name "Alice" ; ex:email "alice@example.org" .
            ex:bob   ex:name "Bob"   ; ex:email "bob@example.org" .
            ex:carol ex:name "Carol" .
            """;
    static final String ORDERED_QUERY = PREFIXES + """
            SELECT ?name ?email ?attestation WHERE {
              SERVICE <urn:x-provenance:attest> {
                SELECT ?name ?email WHERE { ?p ex:name ?name OPTIONAL { ?p ex:email ?email } } ORDER BY ?name
              }
            }
            """;

    DatasetGraph dsg;
    DatasetGraph storeDsg;
    AttestationStore store;
    SigningKey key;

    record Result(List<String> vars, List<Binding> rows) {}

    @BeforeEach
    void setup() {
        dsg = TestLib.assembleVersioned("--mem--");
        Txn.executeWrite(dsg, () -> RDFParser.fromString(DATA, Lang.TTL).parse(dsg));
        storeDsg = DatabaseMgr.createDatasetGraph();
        store = AttestationStore.over(storeDsg);
        key = SigningKey.generate();
        ProvenanceKeys.set(key);
    }

    @AfterEach
    void cleanup() {
        ProvenanceKeys.set(null);
        TDBInternal.reset();
        DataVersion.resetForTesting();
    }

    Result query(DatasetGraph target, String q, Object... settings) {
        var builder = QueryExec.dataset(target).query(q).set(JIP.symAttestationStore, store);
        for ( int i = 0 ; i + 1 < settings.length ; i += 2 )
            builder.set((org.apache.jena.sparql.util.Symbol)settings[i], settings[i + 1]);
        try ( QueryExec qe = builder.build() ) {
            RowSet rs = qe.select();
            List<String> vars = rs.getResultVars().stream().map(Var::getVarName).toList();
            List<Binding> rows = new ArrayList<>();
            rs.forEachRemaining(rows::add);
            return new Result(vars, rows);
        }
    }

    static Set<Node> attestations(Result r, String var) {
        return r.rows().stream().map(b -> b.get(Var.alloc(var))).collect(Collectors.toSet());
    }

    AttestationVerifier.Report verify(Result r, Node attestationIri) {
        Graph g = store.get(attestationIri).orElseThrow(() -> new AssertionError("attestation not stored: " + attestationIri));
        return AttestationVerifier.verify(g, r.vars(), r.rows(), Optional.of(key.didKey()));
    }

    @Test
    void attestsOrderedResult() {
        Result r = query(dsg, ORDERED_QUERY);
        assertEquals(3, r.rows().size());
        assertEquals(List.of("Alice", "Bob", "Carol"),
                     r.rows().stream().map(b -> b.get(Var.alloc("name")).getLiteralLexicalForm()).toList());
        Set<Node> attestations = attestations(r, "attestation");
        assertEquals(1, attestations.size(), "one attestation for one SERVICE call");
        Node attestationIri = attestations.iterator().next();
        assertTrue(attestationIri.getURI().startsWith("urn:uuid:"));

        AttestationVerifier.Report report = verify(r, attestationIri);
        assertTrue(report.valid(), () -> report.problems().toString());
        assertEquals(1, report.dataVersion(), "one write so far");
        assertEquals(3, report.solutionCount());

        Graph g = store.get(attestationIri).orElseThrow();
        assertTrue(g.contains(Node.ANY, Vocab.ordered, NodeFactory.createLiteralDT("true", org.apache.jena.datatypes.xsd.XSDDatatype.XSDboolean)));
        assertTrue(g.contains(Node.ANY, Vocab.queryText, Node.ANY), "full query recorded");
        String pattern = g.find(Node.ANY, Vocab.servicePattern, Node.ANY).next().getObject().getLiteralLexicalForm();
        assertTrue(pattern.contains("?p") && !pattern.contains("?/p"), "service pattern recorded with original names: " + pattern);
        assertTrue(g.contains(Node.ANY, Vocab.provSpecializationOf, NodeFactory.createURI("https://example.org/ds")));

        // Order is part of an ordered attestation.
        List<Binding> reversed = new ArrayList<>(r.rows());
        Collections.reverse(reversed);
        assertFalse(verify(new Result(r.vars(), reversed), attestationIri).digestValid());
    }

    @Test
    void unorderedResultVerifiesInAnyOrder() {
        Result r = query(dsg, PREFIXES + """
                SELECT ?p ?name ?attestation WHERE { SERVICE <urn:x-provenance:attest> { ?p ex:name ?name } }
                """);
        Node attestationIri = attestations(r, "attestation").iterator().next();
        assertTrue(verify(r, attestationIri).valid());
        List<Binding> reversed = new ArrayList<>(r.rows());
        Collections.reverse(reversed);
        assertTrue(verify(new Result(r.vars(), reversed), attestationIri).valid(), "unordered: row order not attested");
    }

    @Test
    void tamperingIsDetected() {
        Result r = query(dsg, ORDERED_QUERY);
        Node attestationIri = attestations(r, "attestation").iterator().next();
        List<Binding> tampered = new ArrayList<>(r.rows());
        Binding first = tampered.get(0);
        BindingBuilder b = BindingBuilder.create();
        first.forEach((v, n) -> b.add(v, v.getVarName().equals("email") ? NodeFactory.createLiteralString("mallory@example.org") : n));
        tampered.set(0, b.build());

        AttestationVerifier.Report report = verify(new Result(r.vars(), tampered), attestationIri);
        assertTrue(report.signatureValid(), "attestation itself untouched");
        assertFalse(report.digestValid());
        assertFalse(report.valid());

        AttestationVerifier.Report dropped = verify(new Result(r.vars(), r.rows().subList(0, 2)), attestationIri);
        assertFalse(dropped.valid(), "dropping a row is detected");
    }

    @Test
    void emptyResultGetsAttestationRowByDefault() {
        Result r = query(dsg, PREFIXES + """
                SELECT ?p ?attestation WHERE { SERVICE <urn:x-provenance:attest> { ?p ex:name "Nobody" } }
                """);
        assertEquals(1, r.rows().size(), "attestation-only row");
        assertNull(r.rows().get(0).get(Var.alloc("p")));
        Node attestationIri = r.rows().get(0).get(Var.alloc("attestation"));
        AttestationVerifier.Report report = verify(r, attestationIri);
        assertTrue(report.valid(), () -> report.problems().toString());
        assertEquals(0, report.solutionCount());

        Result none = query(dsg, PREFIXES + """
                SELECT ?p ?attestation WHERE { SERVICE <urn:x-provenance:attest?empty=none> { ?p ex:name "Nobody" } }
                """);
        assertTrue(none.rows().isEmpty());
    }

    @Test
    void customVariableAndConflict() {
        Result r = query(dsg, PREFIXES + """
                SELECT ?name ?prov WHERE { SERVICE <urn:x-provenance:attest?var=prov> { ?p ex:name ?name } }
                """);
        assertEquals(1, attestations(r, "prov").size());
        assertNotNull(r.rows().get(0).get(Var.alloc("prov")));

        assertThrows(QueryExecException.class, () -> query(dsg, PREFIXES + """
                SELECT * WHERE { SERVICE <urn:x-provenance:attest> { ?attestation ex:name ?name } }
                """));
    }

    @Test
    void capIsEnforcedNotTruncated() {
        String q = PREFIXES + "SELECT ?name ?attestation WHERE { SERVICE <urn:x-provenance:attest> { ?p ex:name ?name } }";
        QueryExecException ex = assertThrows(QueryExecException.class, () -> query(dsg, q, JIP.symMaxSolutions, "2"));
        assertTrue(ex.getMessage().contains("exceeds 2"));
        assertEquals(3, query(dsg, q, JIP.symMaxSolutions, "3").rows().size());
    }

    @Test
    void unversionedDatasetFailsUnlessSilent() {
        DatasetGraph plain = DatabaseMgr.createDatasetGraph();
        String q = PREFIXES + "SELECT * WHERE { SERVICE <urn:x-provenance:attest> { ?p ex:name ?name } }";
        assertThrows(QueryExecException.class, () -> query(plain, q));
        Result silent = query(plain, q.replace("SERVICE", "SERVICE SILENT"));
        assertEquals(1, silent.rows().size(), "SILENT returns the incoming (empty) row");
    }

    @Test
    void refusesInsideWriteTransaction() {
        assertThrows(QueryExecException.class, () -> Txn.executeWrite(dsg, () -> query(dsg, ORDERED_QUERY)));
    }

    @Test
    void attestationsFollowTheDataVersion() {
        Node attestation1 = attestations(query(dsg, ORDERED_QUERY), "attestation").iterator().next();
        Txn.executeWrite(dsg, () -> UpdateExec.dataset(dsg).update(PREFIXES + "INSERT DATA { ex:dave ex:name \"Dave\" }").execute());
        Result r2 = query(dsg, ORDERED_QUERY);
        Node attestation2 = attestations(r2, "attestation").iterator().next();
        assertNotEquals(attestation1, attestation2);
        assertEquals(4, r2.rows().size());
        assertEquals(1, verify(r2, attestation2).dataVersion() - 1, "update bumped v1 -> v2");
        assertEquals(2, verify(r2, attestation2).dataVersion());
    }

    @Test
    void worksInsideExplicitReadTransactionAndOutside() {
        Result inside = Txn.calculateRead(dsg, () -> query(dsg, ORDERED_QUERY));
        assertTrue(verify(inside, attestations(inside, "attestation").iterator().next()).valid());
        Result outside = query(dsg, ORDERED_QUERY);
        assertTrue(verify(outside, attestations(outside, "attestation").iterator().next()).valid());
    }

    @Test
    void attestationIsTimestampedWhenAuthoritiesAreConfigured() throws Exception {
        try ( TestTsa tsa = new TestTsa() ) {
            URI url = tsa.start();
            TimestampAuthorities authorities = TimestampAuthorities.of(List.of(url), TimestampAuthorities.Policy.REQUIRED, TimestampAuthorities.Mode.SYNC, Duration.ofSeconds(5), TimestampAuthorities.DEFAULT_MAX_WAIT);
            Result r = query(dsg, ORDERED_QUERY, JIP.symTimestampAuthorities, authorities);
            Node attestationIri = attestations(r, "attestation").iterator().next();
            Graph g = store.get(attestationIri).orElseThrow();
            assertTrue(g.contains(attestationIri, Vocab.timestamp, Node.ANY));
            assertTrue(g.contains(Node.ANY, Vocab.timestampAuthority, NodeFactory.createURI(url.toString())));

            AttestationVerifier.Options trusting = new AttestationVerifier.Options(Optional.of(key.didKey()), Optional.of(tsa.anchors()), true);
            AttestationVerifier.Report report = AttestationVerifier.verify(g, r.vars(), r.rows(), trusting);
            assertTrue(report.valid(), () -> report.problems().toString());
            assertEquals(1, report.timestamps().size());
            assertEquals(Boolean.TRUE, report.timestamps().get(0).token().trusted());

            // The JVM trust store doesn't know the test CA: reported, but only fatal when required.
            AttestationVerifier.Report system = verify(r, attestationIri);
            assertTrue(system.valid(), () -> system.problems().toString());
            assertEquals(Boolean.FALSE, system.timestamps().get(0).token().trusted());
            AttestationVerifier.Report systemRequired = AttestationVerifier.verify(g, r.vars(), r.rows(),
                    new AttestationVerifier.Options(Optional.of(key.didKey()), Optional.of(Rfc3161.systemTrustAnchors()), true));
            assertFalse(systemRequired.valid());
        }
    }

    @Test
    void timestampPolicyDecidesWhenNoAuthorityAnswers() throws Exception {
        URI dead;
        try ( ServerSocket s = new ServerSocket(0) ) {
            dead = URI.create("http://127.0.0.1:" + s.getLocalPort() + "/tsa");
        }
        TimestampAuthorities required = TimestampAuthorities.of(List.of(dead), TimestampAuthorities.Policy.REQUIRED, TimestampAuthorities.Mode.SYNC, Duration.ofSeconds(2), TimestampAuthorities.DEFAULT_MAX_WAIT);
        QueryExecException ex = assertThrows(QueryExecException.class, () -> query(dsg, ORDERED_QUERY, JIP.symTimestampAuthorities, required));
        assertTrue(ex.getMessage().contains("timestamp is required"), ex.getMessage());

        TimestampAuthorities optional = TimestampAuthorities.of(List.of(dead), TimestampAuthorities.Policy.OPTIONAL, TimestampAuthorities.Mode.SYNC, Duration.ofSeconds(2), TimestampAuthorities.DEFAULT_MAX_WAIT);
        Result r = query(dsg, ORDERED_QUERY, JIP.symTimestampAuthorities, optional);
        Node attestationIri = attestations(r, "attestation").iterator().next();
        AttestationVerifier.Report report = verify(r, attestationIri);
        assertTrue(report.valid(), "attestation without a timestamp is still valid");
        assertTrue(report.timestamps().isEmpty());
        AttestationVerifier.Report requiring = AttestationVerifier.verify(store.get(attestationIri).orElseThrow(), r.vars(), r.rows(),
                new AttestationVerifier.Options(Optional.of(key.didKey()), Optional.empty(), true));
        assertFalse(requiring.valid(), "verifier asked to require a timestamp");
    }

    /** Wait (up to 15 s) until the attestation is no longer pending. */
    void awaitLanded(Node attestationIri) throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(15).toNanos();
        while ( store.pendingSince(attestationIri).isPresent() ) {
            if ( System.nanoTime() > deadline )
                fail("timestamp of " + attestationIri + " did not land");
            Thread.sleep(50);
        }
    }

    @Test
    void asyncTimestampDoesNotBlockTheQuery() throws Exception {
        try ( GatedTsa gated = new GatedTsa() ) {
            TimestampAuthorities authorities = GatedTsa.async(List.of(gated.url()), TimestampAuthorities.Policy.REQUIRED,
                                                              TimestampAuthorities.DEFAULT_MAX_WAIT);
            long t0 = System.nanoTime();
            Result r = query(dsg, ORDERED_QUERY, JIP.symTimestampAuthorities, authorities);
            assertTrue(Duration.ofNanos(System.nanoTime() - t0).toSeconds() < 10, "query did not wait for the TSA (it holds replies 30 s)");
            Node attestationIri = attestations(r, "attestation").iterator().next();

            // Stored, signed and valid, but pending: no timestamp yet.
            assertTrue(store.pendingSince(attestationIri).isPresent());
            assertEquals(List.of(attestationIri), store.pending());
            assertTrue(authorities.isQueued(attestationIri));
            Graph before = store.get(attestationIri).orElseThrow();
            assertFalse(before.contains(attestationIri, Vocab.timestamp, Node.ANY));
            assertTrue(verify(r, attestationIri).valid());

            gated.open();
            awaitLanded(attestationIri);
            assertFalse(authorities.isQueued(attestationIri));
            Graph after = store.get(attestationIri).orElseThrow();
            assertTrue(after.contains(attestationIri, Vocab.timestamp, Node.ANY));
            AttestationVerifier.Report report = AttestationVerifier.verify(after, r.vars(), r.rows(),
                    new AttestationVerifier.Options(Optional.of(key.didKey()), Optional.of(gated.tsa().anchors()), true));
            assertTrue(report.valid(), () -> report.problems().toString());
            assertEquals(1, report.timestamps().size());
        }
    }

    @Test
    void asyncOptionalPolicyReleasesTheAttestationAfterMaxWait() throws Exception {
        URI dead;
        try ( ServerSocket s = new ServerSocket(0) ) {
            dead = URI.create("http://127.0.0.1:" + s.getLocalPort() + "/tsa");
        }
        TimestampAuthorities authorities = GatedTsa.async(List.of(dead), TimestampAuthorities.Policy.OPTIONAL, Duration.ofMillis(300));
        Result r = query(dsg, ORDERED_QUERY, JIP.symTimestampAuthorities, authorities);
        Node attestationIri = attestations(r, "attestation").iterator().next();
        awaitLanded(attestationIri);
        Graph g = store.get(attestationIri).orElseThrow();
        assertFalse(g.contains(attestationIri, Vocab.timestamp, Node.ANY), "released without a timestamp");
        assertTrue(verify(r, attestationIri).valid());
    }

    @Test
    void asyncRequiredPolicyKeepsRetrying() throws Exception {
        URI dead;
        try ( ServerSocket s = new ServerSocket(0) ) {
            dead = URI.create("http://127.0.0.1:" + s.getLocalPort() + "/tsa");
        }
        TimestampAuthorities authorities = GatedTsa.async(List.of(dead), TimestampAuthorities.Policy.REQUIRED, Duration.ofMillis(300));
        Result r = query(dsg, ORDERED_QUERY, JIP.symTimestampAuthorities, authorities);
        Node attestationIri = attestations(r, "attestation").iterator().next();
        Thread.sleep(800);
        assertTrue(store.pendingSince(attestationIri).isPresent(), "still pending past maxWait: the timestamp is required");
        assertTrue(authorities.untilNextAttempt(attestationIri).isPresent(), "another attempt is scheduled");
    }

    @Test
    void pendingTimestampsResumeAfterRestart() throws Exception {
        Node attestationIri;
        try ( GatedTsa gated = new GatedTsa() ) {
            // "Before the restart": the TSA never answers in time.
            TimestampAuthorities first = GatedTsa.async(List.of(gated.url()), TimestampAuthorities.Policy.REQUIRED,
                                                        TimestampAuthorities.DEFAULT_MAX_WAIT);
            Result r = query(dsg, ORDERED_QUERY, JIP.symTimestampAuthorities, first);
            attestationIri = attestations(r, "attestation").iterator().next();
            assertTrue(store.pendingSince(attestationIri).isPresent());

            // "After the restart": a fresh worker picks the attestation up from the store.
            try ( TestTsa good = new TestTsa() ) {
                URI url = good.start();
                TimestampAuthorities second = GatedTsa.async(List.of(url), TimestampAuthorities.Policy.REQUIRED,
                                                             TimestampAuthorities.DEFAULT_MAX_WAIT);
                org.apache.jena.sparql.util.Context cxt = new org.apache.jena.sparql.util.Context();
                cxt.set(JIP.symAttestationStore, store);
                cxt.set(JIP.symTimestampAuthorities, second);
                assertEquals(1, TimestampAuthorities.resumePending(cxt));
                awaitLanded(attestationIri);
            }
            // The first worker's request completes later; the attestation must not get a second token.
            gated.open();
            Thread.sleep(500);
        }
        assertEquals(1, store.get(attestationIri).orElseThrow().find(attestationIri, Vocab.timestamp, Node.ANY).toList().size());
    }

    @Test
    void pendingAttestationsAreReleasedWhenTimestampsAreOff() {
        Graph g = org.apache.jena.graph.GraphMemFactory.createDefaultGraph();
        Node attestationIri = NodeFactory.createURI("urn:uuid:00000000-0000-4000-8000-000000000001");
        g.add(attestationIri, Vocab.digest, NodeFactory.createLiteralString("x"));
        store.storePending(attestationIri, g, java.time.Instant.now());
        org.apache.jena.sparql.util.Context cxt = new org.apache.jena.sparql.util.Context();
        cxt.set(JIP.symAttestationStore, store);
        assertEquals(1, TimestampAuthorities.resumePending(cxt));
        assertTrue(store.pendingSince(attestationIri).isEmpty());
        assertTrue(store.get(attestationIri).isPresent());
    }

    @Test
    void correlatedServiceAttestsEachCall() {
        // TDB2 needs a transaction around lazily evaluated patterns (Fuseki always provides one).
        Result r = Txn.calculateRead(dsg, () -> query(dsg, PREFIXES + """
                SELECT ?p ?name ?email ?attestation WHERE {
                  ?p ex:name ?name .
                  SERVICE <urn:x-provenance:attest> { ?p ex:email ?email }
                }
                """));
        // Alice and Bob have an email; Carol's call is empty and yields an attestation-only row.
        assertEquals(3, r.rows().size());
        assertEquals(3, attestations(r, "attestation").size(), "one attestation per SERVICE call");
        r.rows().forEach(b -> assertNotNull(b.get(Var.alloc("p")), "parent binding kept"));
    }
}
