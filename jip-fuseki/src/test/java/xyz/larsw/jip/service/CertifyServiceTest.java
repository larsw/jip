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
import xyz.larsw.jip.cert.CertificateStore;
import xyz.larsw.jip.cert.CertificateVerifier;
import xyz.larsw.jip.cert.GatedTsa;
import xyz.larsw.jip.cert.ProvenanceKeys;
import xyz.larsw.jip.cert.Rfc3161;
import xyz.larsw.jip.cert.SigningKey;
import xyz.larsw.jip.cert.TestTsa;
import xyz.larsw.jip.cert.TimestampAuthorities;
import xyz.larsw.jip.cert.Vocab;
import xyz.larsw.jip.version.DataVersion;
import xyz.larsw.jip.TestLib;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CertifyServiceTest {

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
            SELECT ?name ?email ?cert WHERE {
              SERVICE <urn:x-provenance:certify> {
                SELECT ?name ?email WHERE { ?p ex:name ?name OPTIONAL { ?p ex:email ?email } } ORDER BY ?name
              }
            }
            """;

    DatasetGraph dsg;
    DatasetGraph storeDsg;
    CertificateStore store;
    SigningKey key;

    record Result(List<String> vars, List<Binding> rows) {}

    @BeforeEach
    void setup() {
        dsg = TestLib.assembleVersioned("--mem--");
        Txn.executeWrite(dsg, () -> RDFParser.fromString(DATA, Lang.TTL).parse(dsg));
        storeDsg = DatabaseMgr.createDatasetGraph();
        store = CertificateStore.over(storeDsg);
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
        var builder = QueryExec.dataset(target).query(q).set(JIP.symCertificateStore, store);
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

    static Set<Node> certs(Result r, String var) {
        return r.rows().stream().map(b -> b.get(Var.alloc(var))).collect(Collectors.toSet());
    }

    CertificateVerifier.Report verify(Result r, Node cert) {
        Graph g = store.get(cert).orElseThrow(() -> new AssertionError("certificate not stored: " + cert));
        return CertificateVerifier.verify(g, r.vars(), r.rows(), Optional.of(key.didKey()));
    }

    @Test
    void certifiesOrderedResult() {
        Result r = query(dsg, ORDERED_QUERY);
        assertEquals(3, r.rows().size());
        assertEquals(List.of("Alice", "Bob", "Carol"),
                     r.rows().stream().map(b -> b.get(Var.alloc("name")).getLiteralLexicalForm()).toList());
        Set<Node> certs = certs(r, "cert");
        assertEquals(1, certs.size(), "one certificate for one SERVICE call");
        Node cert = certs.iterator().next();
        assertTrue(cert.getURI().startsWith("urn:uuid:"));

        CertificateVerifier.Report report = verify(r, cert);
        assertTrue(report.valid(), () -> report.problems().toString());
        assertEquals(1, report.dataVersion(), "one write so far");
        assertEquals(3, report.solutionCount());

        Graph g = store.get(cert).orElseThrow();
        assertTrue(g.contains(Node.ANY, Vocab.ordered, NodeFactory.createLiteralDT("true", org.apache.jena.datatypes.xsd.XSDDatatype.XSDboolean)));
        assertTrue(g.contains(Node.ANY, Vocab.queryText, Node.ANY), "full query recorded");
        String pattern = g.find(Node.ANY, Vocab.servicePattern, Node.ANY).next().getObject().getLiteralLexicalForm();
        assertTrue(pattern.contains("?p") && !pattern.contains("?/p"), "service pattern recorded with original names: " + pattern);
        assertTrue(g.contains(Node.ANY, Vocab.provSpecializationOf, NodeFactory.createURI("https://example.org/ds")));

        // Order is part of an ordered certificate.
        List<Binding> reversed = new ArrayList<>(r.rows());
        Collections.reverse(reversed);
        assertFalse(verify(new Result(r.vars(), reversed), cert).digestValid());
    }

    @Test
    void unorderedResultVerifiesInAnyOrder() {
        Result r = query(dsg, PREFIXES + """
                SELECT ?p ?name ?cert WHERE { SERVICE <urn:x-provenance:certify> { ?p ex:name ?name } }
                """);
        Node cert = certs(r, "cert").iterator().next();
        assertTrue(verify(r, cert).valid());
        List<Binding> reversed = new ArrayList<>(r.rows());
        Collections.reverse(reversed);
        assertTrue(verify(new Result(r.vars(), reversed), cert).valid(), "unordered: row order not certified");
    }

    @Test
    void tamperingIsDetected() {
        Result r = query(dsg, ORDERED_QUERY);
        Node cert = certs(r, "cert").iterator().next();
        List<Binding> tampered = new ArrayList<>(r.rows());
        Binding first = tampered.get(0);
        BindingBuilder b = BindingBuilder.create();
        first.forEach((v, n) -> b.add(v, v.getVarName().equals("email") ? NodeFactory.createLiteralString("mallory@example.org") : n));
        tampered.set(0, b.build());

        CertificateVerifier.Report report = verify(new Result(r.vars(), tampered), cert);
        assertTrue(report.signatureValid(), "certificate itself untouched");
        assertFalse(report.digestValid());
        assertFalse(report.valid());

        CertificateVerifier.Report dropped = verify(new Result(r.vars(), r.rows().subList(0, 2)), cert);
        assertFalse(dropped.valid(), "dropping a row is detected");
    }

    @Test
    void emptyResultGetsCertificateRowByDefault() {
        Result r = query(dsg, PREFIXES + """
                SELECT ?p ?cert WHERE { SERVICE <urn:x-provenance:certify> { ?p ex:name "Nobody" } }
                """);
        assertEquals(1, r.rows().size(), "certificate-only row");
        assertNull(r.rows().get(0).get(Var.alloc("p")));
        Node cert = r.rows().get(0).get(Var.alloc("cert"));
        CertificateVerifier.Report report = verify(r, cert);
        assertTrue(report.valid(), () -> report.problems().toString());
        assertEquals(0, report.solutionCount());

        Result none = query(dsg, PREFIXES + """
                SELECT ?p ?cert WHERE { SERVICE <urn:x-provenance:certify?empty=none> { ?p ex:name "Nobody" } }
                """);
        assertTrue(none.rows().isEmpty());
    }

    @Test
    void customVariableAndConflict() {
        Result r = query(dsg, PREFIXES + """
                SELECT ?name ?prov WHERE { SERVICE <urn:x-provenance:certify?var=prov> { ?p ex:name ?name } }
                """);
        assertEquals(1, certs(r, "prov").size());
        assertNotNull(r.rows().get(0).get(Var.alloc("prov")));

        assertThrows(QueryExecException.class, () -> query(dsg, PREFIXES + """
                SELECT * WHERE { SERVICE <urn:x-provenance:certify> { ?cert ex:name ?name } }
                """));
    }

    @Test
    void capIsEnforcedNotTruncated() {
        String q = PREFIXES + "SELECT ?name ?cert WHERE { SERVICE <urn:x-provenance:certify> { ?p ex:name ?name } }";
        QueryExecException ex = assertThrows(QueryExecException.class, () -> query(dsg, q, JIP.symMaxSolutions, "2"));
        assertTrue(ex.getMessage().contains("exceeds 2"));
        assertEquals(3, query(dsg, q, JIP.symMaxSolutions, "3").rows().size());
    }

    @Test
    void unversionedDatasetFailsUnlessSilent() {
        DatasetGraph plain = DatabaseMgr.createDatasetGraph();
        String q = PREFIXES + "SELECT * WHERE { SERVICE <urn:x-provenance:certify> { ?p ex:name ?name } }";
        assertThrows(QueryExecException.class, () -> query(plain, q));
        Result silent = query(plain, q.replace("SERVICE", "SERVICE SILENT"));
        assertEquals(1, silent.rows().size(), "SILENT returns the incoming (empty) row");
    }

    @Test
    void refusesInsideWriteTransaction() {
        assertThrows(QueryExecException.class, () -> Txn.executeWrite(dsg, () -> query(dsg, ORDERED_QUERY)));
    }

    @Test
    void certificatesFollowTheDataVersion() {
        Node cert1 = certs(query(dsg, ORDERED_QUERY), "cert").iterator().next();
        Txn.executeWrite(dsg, () -> UpdateExec.dataset(dsg).update(PREFIXES + "INSERT DATA { ex:dave ex:name \"Dave\" }").execute());
        Result r2 = query(dsg, ORDERED_QUERY);
        Node cert2 = certs(r2, "cert").iterator().next();
        assertNotEquals(cert1, cert2);
        assertEquals(4, r2.rows().size());
        assertEquals(1, verify(r2, cert2).dataVersion() - 1, "update bumped v1 -> v2");
        assertEquals(2, verify(r2, cert2).dataVersion());
    }

    @Test
    void worksInsideExplicitReadTransactionAndOutside() {
        Result inside = Txn.calculateRead(dsg, () -> query(dsg, ORDERED_QUERY));
        assertTrue(verify(inside, certs(inside, "cert").iterator().next()).valid());
        Result outside = query(dsg, ORDERED_QUERY);
        assertTrue(verify(outside, certs(outside, "cert").iterator().next()).valid());
    }

    @Test
    void certificateIsTimestampedWhenAuthoritiesAreConfigured() throws Exception {
        try ( TestTsa tsa = new TestTsa() ) {
            URI url = tsa.start();
            TimestampAuthorities authorities = TimestampAuthorities.of(List.of(url), TimestampAuthorities.Policy.REQUIRED, TimestampAuthorities.Mode.SYNC, Duration.ofSeconds(5), TimestampAuthorities.DEFAULT_MAX_WAIT);
            Result r = query(dsg, ORDERED_QUERY, JIP.symTimestampAuthorities, authorities);
            Node cert = certs(r, "cert").iterator().next();
            Graph g = store.get(cert).orElseThrow();
            assertTrue(g.contains(cert, Vocab.timestamp, Node.ANY));
            assertTrue(g.contains(Node.ANY, Vocab.timestampAuthority, NodeFactory.createURI(url.toString())));

            CertificateVerifier.Options trusting = new CertificateVerifier.Options(Optional.of(key.didKey()), Optional.of(tsa.anchors()), true);
            CertificateVerifier.Report report = CertificateVerifier.verify(g, r.vars(), r.rows(), trusting);
            assertTrue(report.valid(), () -> report.problems().toString());
            assertEquals(1, report.timestamps().size());
            assertEquals(Boolean.TRUE, report.timestamps().get(0).token().trusted());

            // The JVM trust store doesn't know the test CA: reported, but only fatal when required.
            CertificateVerifier.Report system = verify(r, cert);
            assertTrue(system.valid(), () -> system.problems().toString());
            assertEquals(Boolean.FALSE, system.timestamps().get(0).token().trusted());
            CertificateVerifier.Report systemRequired = CertificateVerifier.verify(g, r.vars(), r.rows(),
                    new CertificateVerifier.Options(Optional.of(key.didKey()), Optional.of(Rfc3161.systemTrustAnchors()), true));
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
        Node cert = certs(r, "cert").iterator().next();
        CertificateVerifier.Report report = verify(r, cert);
        assertTrue(report.valid(), "certificate without a timestamp is still valid");
        assertTrue(report.timestamps().isEmpty());
        CertificateVerifier.Report requiring = CertificateVerifier.verify(store.get(cert).orElseThrow(), r.vars(), r.rows(),
                new CertificateVerifier.Options(Optional.of(key.didKey()), Optional.empty(), true));
        assertFalse(requiring.valid(), "verifier asked to require a timestamp");
    }

    /** Wait (up to 15 s) until the certificate is no longer pending. */
    void awaitLanded(Node cert) throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(15).toNanos();
        while ( store.pendingSince(cert).isPresent() ) {
            if ( System.nanoTime() > deadline )
                fail("timestamp of " + cert + " did not land");
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
            Node cert = certs(r, "cert").iterator().next();

            // Stored, signed and valid, but pending: no timestamp yet.
            assertTrue(store.pendingSince(cert).isPresent());
            assertEquals(List.of(cert), store.pending());
            assertTrue(authorities.isQueued(cert));
            Graph before = store.get(cert).orElseThrow();
            assertFalse(before.contains(cert, Vocab.timestamp, Node.ANY));
            assertTrue(verify(r, cert).valid());

            gated.open();
            awaitLanded(cert);
            assertFalse(authorities.isQueued(cert));
            Graph after = store.get(cert).orElseThrow();
            assertTrue(after.contains(cert, Vocab.timestamp, Node.ANY));
            CertificateVerifier.Report report = CertificateVerifier.verify(after, r.vars(), r.rows(),
                    new CertificateVerifier.Options(Optional.of(key.didKey()), Optional.of(gated.tsa().anchors()), true));
            assertTrue(report.valid(), () -> report.problems().toString());
            assertEquals(1, report.timestamps().size());
        }
    }

    @Test
    void asyncOptionalPolicyReleasesTheCertificateAfterMaxWait() throws Exception {
        URI dead;
        try ( ServerSocket s = new ServerSocket(0) ) {
            dead = URI.create("http://127.0.0.1:" + s.getLocalPort() + "/tsa");
        }
        TimestampAuthorities authorities = GatedTsa.async(List.of(dead), TimestampAuthorities.Policy.OPTIONAL, Duration.ofMillis(300));
        Result r = query(dsg, ORDERED_QUERY, JIP.symTimestampAuthorities, authorities);
        Node cert = certs(r, "cert").iterator().next();
        awaitLanded(cert);
        Graph g = store.get(cert).orElseThrow();
        assertFalse(g.contains(cert, Vocab.timestamp, Node.ANY), "released without a timestamp");
        assertTrue(verify(r, cert).valid());
    }

    @Test
    void asyncRequiredPolicyKeepsRetrying() throws Exception {
        URI dead;
        try ( ServerSocket s = new ServerSocket(0) ) {
            dead = URI.create("http://127.0.0.1:" + s.getLocalPort() + "/tsa");
        }
        TimestampAuthorities authorities = GatedTsa.async(List.of(dead), TimestampAuthorities.Policy.REQUIRED, Duration.ofMillis(300));
        Result r = query(dsg, ORDERED_QUERY, JIP.symTimestampAuthorities, authorities);
        Node cert = certs(r, "cert").iterator().next();
        Thread.sleep(800);
        assertTrue(store.pendingSince(cert).isPresent(), "still pending past maxWait: the timestamp is required");
        assertTrue(authorities.untilNextAttempt(cert).isPresent(), "another attempt is scheduled");
    }

    @Test
    void pendingTimestampsResumeAfterRestart() throws Exception {
        Node cert;
        try ( GatedTsa gated = new GatedTsa() ) {
            // "Before the restart": the TSA never answers in time.
            TimestampAuthorities first = GatedTsa.async(List.of(gated.url()), TimestampAuthorities.Policy.REQUIRED,
                                                        TimestampAuthorities.DEFAULT_MAX_WAIT);
            Result r = query(dsg, ORDERED_QUERY, JIP.symTimestampAuthorities, first);
            cert = certs(r, "cert").iterator().next();
            assertTrue(store.pendingSince(cert).isPresent());

            // "After the restart": a fresh worker picks the certificate up from the store.
            try ( TestTsa good = new TestTsa() ) {
                URI url = good.start();
                TimestampAuthorities second = GatedTsa.async(List.of(url), TimestampAuthorities.Policy.REQUIRED,
                                                             TimestampAuthorities.DEFAULT_MAX_WAIT);
                org.apache.jena.sparql.util.Context cxt = new org.apache.jena.sparql.util.Context();
                cxt.set(JIP.symCertificateStore, store);
                cxt.set(JIP.symTimestampAuthorities, second);
                assertEquals(1, TimestampAuthorities.resumePending(cxt));
                awaitLanded(cert);
            }
            // The first worker's request completes later; the certificate must not get a second token.
            gated.open();
            Thread.sleep(500);
        }
        assertEquals(1, store.get(cert).orElseThrow().find(cert, Vocab.timestamp, Node.ANY).toList().size());
    }

    @Test
    void pendingCertificatesAreReleasedWhenTimestampsAreOff() {
        Graph g = org.apache.jena.graph.GraphMemFactory.createDefaultGraph();
        Node cert = NodeFactory.createURI("urn:uuid:00000000-0000-4000-8000-000000000001");
        g.add(cert, Vocab.digest, NodeFactory.createLiteralString("x"));
        store.storePending(cert, g, java.time.Instant.now());
        org.apache.jena.sparql.util.Context cxt = new org.apache.jena.sparql.util.Context();
        cxt.set(JIP.symCertificateStore, store);
        assertEquals(1, TimestampAuthorities.resumePending(cxt));
        assertTrue(store.pendingSince(cert).isEmpty());
        assertTrue(store.get(cert).isPresent());
    }

    @Test
    void correlatedServiceCertifiesEachCall() {
        // TDB2 needs a transaction around lazily evaluated patterns (Fuseki always provides one).
        Result r = Txn.calculateRead(dsg, () -> query(dsg, PREFIXES + """
                SELECT ?p ?name ?email ?cert WHERE {
                  ?p ex:name ?name .
                  SERVICE <urn:x-provenance:certify> { ?p ex:email ?email }
                }
                """));
        // Alice and Bob have an email; Carol's call is empty and yields a certificate-only row.
        assertEquals(3, r.rows().size());
        assertEquals(3, certs(r, "cert").size(), "one certificate per SERVICE call");
        r.rows().forEach(b -> assertNotNull(b.get(Var.alloc("p")), "parent binding kept"));
    }
}
