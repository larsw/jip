package org.example.jena.provenance.service;

import static org.junit.jupiter.api.Assertions.*;

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
import org.example.jena.provenance.JIP;
import org.example.jena.provenance.cert.CertificateStore;
import org.example.jena.provenance.cert.CertificateVerifier;
import org.example.jena.provenance.cert.ProvenanceKeys;
import org.example.jena.provenance.cert.SigningKey;
import org.example.jena.provenance.cert.Vocab;
import org.example.jena.provenance.version.DataVersion;
import org.example.jena.provenance.TestLib;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CertifyServiceTest {

    static final String PREFIXES = """
            PREFIX ex:  <http://example.org/>
            PREFIX jip: <https://larsw.github.io/jip#>
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
