package org.example.jena.provenance.cert;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.TreeSet;

import org.apache.jena.graph.Graph;
import org.apache.jena.graph.Node;
import org.apache.jena.graph.Triple;
import org.apache.jena.sparql.core.Var;
import org.apache.jena.sparql.engine.binding.Binding;
import org.apache.jena.vocabulary.RDF;
import org.example.jena.provenance.canon.ResultSetEncoding;

/**
 * Verifies a certificate and the result rows it claims to certify, independently of the server.
 * <ol>
 * <li>Check the {@code eddsa-rdfc-2022} proof against its {@code did:key} (optionally pinned).</li>
 * <li>Select the rows carrying this certificate's IRI.</li>
 * <li>Rebuild the {@code rs:} encoding from the certified variables ({@code rs:index} only if
 * the certificate says ordered), canonicalize with RDFC-1.0, compare SHA-256 digests.</li>
 * </ol>
 */
public final class CertificateVerifier {
    private CertificateVerifier() {}

    public record Report(Node certificate,
                         boolean signatureValid,
                         boolean digestValid,
                         String verificationMethod,
                         long dataVersion,
                         Node datasetState,
                         int solutionCount,
                         int rowsChecked,
                         List<String> problems) {
        public boolean valid() {
            return signatureValid && digestValid && problems.isEmpty();
        }
    }

    /**
     * @param certificate  the certificate graph (as fetched from the server)
     * @param resultVars   the variables of the result set (header)
     * @param rows         all rows of the result set, in order
     * @param expectedKey  optional did:key the signature must come from
     */
    public static Report verify(Graph certificate, Collection<String> resultVars, List<Binding> rows, Optional<String> expectedKey) {
        List<String> problems = new ArrayList<>();
        List<Node> certs = certificate.find(Node.ANY, RDF.type.asNode(), Vocab.ResultCertificate).mapWith(Triple::getSubject).toList();
        if ( certs.size() != 1 )
            return new Report(null, false, false, null, -1, null, -1, 0, List.of("Expected one jip:ResultCertificate, found " + certs.size()));
        Node cert = certs.get(0);

        // 1. Signature
        DataIntegrityProof.Verification sig = DataIntegrityProof.verify(certificate, cert);
        problems.addAll(sig.problems());
        if ( expectedKey.isPresent() && sig.verificationMethod() != null
             && !sig.verificationMethod().startsWith(expectedKey.get() + "#") )
            problems.add("Signed by " + sig.verificationMethod() + ", expected " + expectedKey.get());

        // 2. Claims
        Node result = object(certificate, cert, Vocab.certifies);
        if ( result == null )
            return new Report(cert, sig.valid(), false, sig.verificationMethod(), -1, null, -1, 0, add(problems, "No jip:certifies"));
        TreeSet<String> vars = new TreeSet<>();
        certificate.find(result, Vocab.variable, Node.ANY).forEach(t -> vars.add(t.getObject().getLiteralLexicalForm()));
        boolean ordered = "true".equals(lexical(certificate, result, Vocab.ordered));
        int count = Integer.parseInt(lexical(certificate, result, Vocab.solutionCount));
        String digest = lexical(certificate, result, Vocab.digest);
        Node state = object(certificate, result, Vocab.provWasDerivedFrom);
        String versionLex = state == null ? null : lexical(certificate, state, Vocab.dataVersion);
        long version = versionLex == null ? -1 : Long.parseLong(versionLex);

        for ( String v : vars ) {
            if ( !resultVars.contains(v) )
                problems.add("Result does not include certified variable ?" + v + " (project it in the outer query)");
        }

        // 3. Rows of this certificate
        List<Binding> mine = rows.stream().filter(b -> carries(b, cert)).toList();
        List<Binding> certified;
        if ( count == 0 ) {
            certified = List.of();
            boolean markerOnly = mine.size() == 1 && vars.stream().noneMatch(v -> mine.get(0).contains(Var.alloc(v)));
            if ( !mine.isEmpty() && !markerOnly )
                problems.add("Certificate says 0 solutions but " + mine.size() + " row(s) carry data");
        } else {
            certified = mine;
            if ( mine.size() != count )
                problems.add("Certificate says " + count + " solution(s), result has " + mine.size() + " row(s) with this certificate");
        }
        String actual = ResultSetEncoding.digest(vars, certified, ordered);
        boolean digestOk = actual.equals(digest);
        if ( !digestOk )
            problems.add("Result digest mismatch: certificate " + digest + ", rows " + actual);

        return new Report(cert, sig.valid(), digestOk, sig.verificationMethod(), version, state, count, mine.size(), List.copyOf(problems));
    }

    private static boolean carries(Binding b, Node cert) {
        for ( var it = b.vars() ; it.hasNext() ; ) {
            if ( cert.equals(b.get(it.next())) )
                return true;
        }
        return false;
    }

    private static Node object(Graph g, Node s, Node p) {
        var it = g.find(s, p, Node.ANY);
        return it.hasNext() ? it.next().getObject() : null;
    }

    private static String lexical(Graph g, Node s, Node p) {
        Node o = object(g, s, p);
        return o != null && o.isLiteral() ? o.getLiteralLexicalForm() : null;
    }

    private static List<String> add(List<String> list, String s) {
        list.add(s);
        return list;
    }
}
