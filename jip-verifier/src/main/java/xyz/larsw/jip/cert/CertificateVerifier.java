package xyz.larsw.jip.cert;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.TrustAnchor;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

import org.apache.jena.graph.Graph;
import org.apache.jena.graph.GraphMemFactory;
import org.apache.jena.graph.Node;
import org.apache.jena.graph.Triple;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFLanguages;
import org.apache.jena.riot.RDFParser;
import org.apache.jena.riot.ResultSetMgr;
import org.apache.jena.riot.resultset.ResultSetLang;
import org.apache.jena.riot.system.ErrorHandlerFactory;
import org.apache.jena.sparql.core.Var;
import org.apache.jena.sparql.engine.binding.Binding;
import org.apache.jena.sparql.exec.RowSet;
import org.apache.jena.vocabulary.RDF;
import xyz.larsw.jip.canon.ResultSetEncoding;

/**
 * Verifies a certificate and the result rows it claims to certify, independently of the server.
 * <ol>
 * <li>Check the {@code eddsa-rdfc-2022} proof against its {@code did:key} (optionally pinned).</li>
 * <li>Check any RFC 3161 timestamps over the signature ({@link CertificateTimestamps}).</li>
 * <li>Select the rows carrying this certificate's IRI.</li>
 * <li>Rebuild the {@code rs:} encoding from the certified variables ({@code rs:index} only if
 * the certificate says ordered), canonicalize with RDFC-1.0, compare SHA-256 digests.</li>
 * </ol>
 * Entry points, from most to least convenient:
 * <ul>
 * <li>{@link #verify(Path, Path, Optional)}: a certificate file and a SPARQL results file.</li>
 * <li>{@link #verify(Graph, RowSet, Optional)}: a parsed certificate and a result row set, for
 * example straight from a query execution.</li>
 * <li>{@link #verify(Graph, Collection, List, Optional)}: variables and rows already in hand.</li>
 * </ul>
 * None of them needs the server, TDB2 or the signing key; the public key comes from the
 * {@code did:key} in the proof. Pass {@code expectedKey} to pin the key you trust.
 */
public final class CertificateVerifier {
    private CertificateVerifier() {}

    /**
     * @param timestamps  the RFC 3161 timestamps on the certificate, each checked; a broken
     *                    timestamp is also listed in {@code problems}, an untrusted one is not
     *                    (unless a timestamp is required, see {@link Options})
     */
    public record Report(Node certificate,
                         boolean signatureValid,
                         boolean digestValid,
                         String verificationMethod,
                         long dataVersion,
                         Node datasetState,
                         int solutionCount,
                         int rowsChecked,
                         List<CertificateTimestamps.Check> timestamps,
                         List<String> problems) {
        public boolean valid() {
            return signatureValid && digestValid && problems.isEmpty();
        }
    }

    /**
     * What to check besides the signature and the digest.
     *
     * @param expectedKey       the did:key the signature must come from, if pinned
     * @param tsaTrustAnchors   trust anchors for TSA certificates; empty to skip the chain check
     * @param requireTimestamp  fail unless at least one timestamp is valid and not untrusted
     */
    public record Options(Optional<String> expectedKey, Optional<Set<TrustAnchor>> tsaTrustAnchors, boolean requireTimestamp) {
        /** Optional key pin; TSAs checked against the JVM trust store; timestamps optional. */
        public static Options defaults(Optional<String> expectedKey) {
            return new Options(expectedKey, Optional.of(Rfc3161.systemTrustAnchors()), false);
        }
    }

    /** A SPARQL result set read into memory: its variables and its rows, in order. */
    public record Results(List<String> variables, List<Binding> rows) {
        public Results {
            variables = List.copyOf(variables);
            rows = List.copyOf(rows);
        }
    }

    /**
     * Verify a certificate file against a SPARQL results file.
     *
     * @param certificateFile  RDF; the syntax comes from the file extension, Turtle if unknown
     * @param resultsFile      SPARQL results; see {@link #readResults(Path)} for the formats
     * @param expectedKey      optional did:key the signature must come from
     * @throws UncheckedIOException if a file cannot be read
     * @throws org.apache.jena.riot.RiotException if a file cannot be parsed
     */
    public static Report verify(Path certificateFile, Path resultsFile, Optional<String> expectedKey) {
        return verify(certificateFile, resultsFile, Options.defaults(expectedKey));
    }

    /** As {@link #verify(Path, Path, Optional)}, with all options. */
    public static Report verify(Path certificateFile, Path resultsFile, Options options) {
        Graph certificate = readCertificate(certificateFile);
        Results results = readResults(resultsFile);
        return verify(certificate, results.variables(), results.rows(), options);
    }

    /**
     * Verify a certificate against a result row set. The row set is consumed.
     *
     * @param certificate  the certificate graph (as fetched from the server)
     * @param results      the result rows, in order
     * @param expectedKey  optional did:key the signature must come from
     */
    public static Report verify(Graph certificate, RowSet results, Optional<String> expectedKey) {
        Results r = read(results);
        return verify(certificate, r.variables(), r.rows(), expectedKey);
    }

    /**
     * @param certificate  the certificate graph (as fetched from the server)
     * @param resultVars   the variables of the result set (header)
     * @param rows         all rows of the result set, in order
     * @param expectedKey  optional did:key the signature must come from
     */
    public static Report verify(Graph certificate, Collection<String> resultVars, List<Binding> rows, Optional<String> expectedKey) {
        return verify(certificate, resultVars, rows, Options.defaults(expectedKey));
    }

    /** As {@link #verify(Graph, Collection, List, Optional)}, with all options. */
    public static Report verify(Graph certificate, Collection<String> resultVars, List<Binding> rows, Options options) {
        List<String> problems = new ArrayList<>();
        List<Node> certs = certificate.find(Node.ANY, RDF.type.asNode(), Vocab.ResultCertificate).mapWith(Triple::getSubject).toList();
        if ( certs.size() != 1 )
            return new Report(null, false, false, null, -1, null, -1, 0, List.of(),
                              List.of("Expected one jip:ResultCertificate, found " + certs.size()));
        Node cert = certs.get(0);
        Optional<String> expectedKey = options.expectedKey();

        // 1. Signature, over the certificate without its timestamps (added after signing)
        DataIntegrityProof.Verification sig = DataIntegrityProof.verify(CertificateTimestamps.withoutTimestamps(certificate, cert), cert);
        problems.addAll(sig.problems());
        if ( expectedKey.isPresent() && sig.verificationMethod() != null
             && !sig.verificationMethod().startsWith(expectedKey.get() + "#") )
            problems.add("Signed by " + sig.verificationMethod() + ", expected " + expectedKey.get());

        // 1b. RFC 3161 timestamps over the signature
        List<CertificateTimestamps.Check> timestamps = CertificateTimestamps.verify(certificate, cert, options.tsaTrustAnchors());
        for ( CertificateTimestamps.Check c : timestamps )
            c.token().problems().forEach(p -> problems.add("Timestamp" + (c.authority() == null ? "" : " from " + c.authority()) + ": " + p));
        if ( options.requireTimestamp() && timestamps.stream().noneMatch(c -> c.token().acceptable()) )
            problems.add(timestamps.isEmpty() ? "No RFC 3161 timestamp, and one is required"
                                              : "No valid, trusted RFC 3161 timestamp, and one is required");

        // 2. Claims
        Node result = object(certificate, cert, Vocab.certifies);
        if ( result == null )
            return new Report(cert, sig.valid(), false, sig.verificationMethod(), -1, null, -1, 0, timestamps,
                              add(problems, "No jip:certifies"));
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

        return new Report(cert, sig.valid(), digestOk, sig.verificationMethod(), version, state, count, mine.size(), timestamps,
                          List.copyOf(problems));
    }

    /**
     * Parse a certificate file. The syntax comes from the file extension (Turtle if it is not
     * recognized).
     */
    public static Graph readCertificate(Path file) {
        Lang lang = RDFLanguages.pathnameToLang(file.toString());
        Graph g = GraphMemFactory.createDefaultGraph();
        // Jena's IRI checker warns about the '#' in did:key verification method IRIs, which
        // DID URL syntax allows; the warning is noise here.
        RDFParser.source(file).lang(lang == null ? Lang.TURTLE : lang)
                .errorHandler(ErrorHandlerFactory.errorHandlerNoWarnings)
                .parse(g);
        return g;
    }

    /**
     * Read a SPARQL results file into memory. The format comes from the file extension:
     * {@code .srx}/{@code .xml} XML, {@code .tsv} TSV, {@code .csv} CSV, anything else JSON.
     * CSV loses term types, so certificates verify reliably only against JSON, XML or TSV.
     */
    public static Results readResults(Path file) {
        String name = file.getFileName().toString().toLowerCase(Locale.ROOT);
        Lang lang = name.endsWith(".srx") || name.endsWith(".xml") ? ResultSetLang.RS_XML
                : name.endsWith(".tsv") ? ResultSetLang.RS_TSV
                : name.endsWith(".csv") ? ResultSetLang.RS_CSV
                : ResultSetLang.RS_JSON;
        try ( InputStream in = Files.newInputStream(file) ) {
            return read(RowSet.adapt(ResultSetMgr.read(in, lang)));
        } catch (IOException ex) {
            throw new UncheckedIOException(file.toString(), ex);
        }
    }

    private static Results read(RowSet rs) {
        List<String> vars = rs.getResultVars().stream().map(Var::getVarName).toList();
        List<Binding> rows = new ArrayList<>();
        rs.forEachRemaining(rows::add);
        return new Results(vars, rows);
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
