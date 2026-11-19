package xyz.larsw.jip.attestation;

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
 * Verifies an attestation and the result rows it claims to attest, independently of the server.
 * <ol>
 * <li>Check the {@code eddsa-rdfc-2022} proof against its {@code did:key} (optionally pinned).</li>
 * <li>Check any RFC 3161 timestamps over the signature ({@link AttestationTimestamps}).</li>
 * <li>Select the rows carrying this attestation's IRI.</li>
 * <li>Rebuild the {@code rs:} encoding from the attested variables ({@code rs:index} only if
 * the attestation says ordered), canonicalize with RDFC-1.0, compare SHA-256 digests.</li>
 * </ol>
 * Entry points, from most to least convenient:
 * <ul>
 * <li>{@link #verify(Path, Path, Optional)}: an attestation file and a SPARQL results file.</li>
 * <li>{@link #verify(Graph, RowSet, Optional)}: a parsed attestation and a result row set, for
 * example straight from a query execution.</li>
 * <li>{@link #verify(Graph, Collection, List, Optional)}: variables and rows already in hand.</li>
 * </ul>
 * None of them needs the server, TDB2 or the signing key; the public key comes from the
 * {@code did:key} in the proof. Pass {@code expectedKey} to pin the key you trust.
 */
public final class AttestationVerifier {
    private AttestationVerifier() {}

    /**
     * @param timestamps  the RFC 3161 timestamps on the attestation, each checked; a broken
     *                    timestamp is also listed in {@code problems}, an untrusted one is not
     *                    (unless a timestamp is required, see {@link Options})
     */
    public record Report(Node attestation,
                         boolean signatureValid,
                         boolean digestValid,
                         String verificationMethod,
                         long dataVersion,
                         Node datasetState,
                         int solutionCount,
                         int rowsChecked,
                         Optional<Requester> requester,
                         List<AttestationTimestamps.Check> timestamps,
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
     * Verify an attestation file against a SPARQL results file.
     *
     * @param attestationFile  RDF; the syntax comes from the file extension, Turtle if unknown
     * @param resultsFile      SPARQL results; see {@link #readResults(Path)} for the formats
     * @param expectedKey      optional did:key the signature must come from
     * @throws UncheckedIOException if a file cannot be read
     * @throws org.apache.jena.riot.RiotException if a file cannot be parsed
     */
    public static Report verify(Path attestationFile, Path resultsFile, Optional<String> expectedKey) {
        return verify(attestationFile, resultsFile, Options.defaults(expectedKey));
    }

    /** As {@link #verify(Path, Path, Optional)}, with all options. */
    public static Report verify(Path attestationFile, Path resultsFile, Options options) {
        Graph attestation = readAttestation(attestationFile);
        Results results = readResults(resultsFile);
        return verify(attestation, results.variables(), results.rows(), options);
    }

    /**
     * Verify an attestation against a result row set. The row set is consumed.
     *
     * @param attestation  the attestation graph (as fetched from the server)
     * @param results      the result rows, in order
     * @param expectedKey  optional did:key the signature must come from
     */
    public static Report verify(Graph attestation, RowSet results, Optional<String> expectedKey) {
        Results r = read(results);
        return verify(attestation, r.variables(), r.rows(), expectedKey);
    }

    /**
     * @param attestation  the attestation graph (as fetched from the server)
     * @param resultVars   the variables of the result set (header)
     * @param rows         all rows of the result set, in order
     * @param expectedKey  optional did:key the signature must come from
     */
    public static Report verify(Graph attestation, Collection<String> resultVars, List<Binding> rows, Optional<String> expectedKey) {
        return verify(attestation, resultVars, rows, Options.defaults(expectedKey));
    }

    /** As {@link #verify(Graph, Collection, List, Optional)}, with all options. */
    public static Report verify(Graph attestation, Collection<String> resultVars, List<Binding> rows, Options options) {
        List<String> problems = new ArrayList<>();
        List<Node> attestationNodes = attestation.find(Node.ANY, RDF.type.asNode(), Vocab.ResultAttestation).mapWith(Triple::getSubject).toList();
        if ( attestationNodes.size() != 1 )
            return new Report(null, false, false, null, -1, null, -1, 0, Optional.empty(), List.of(),
                              List.of("Expected one jip:ResultAttestation, found " + attestationNodes.size()));
        Node attestationIri = attestationNodes.get(0);
        Optional<String> expectedKey = options.expectedKey();

        // 1. Signature, over the attestation without its timestamps (added after signing)
        DataIntegrityProof.Verification sig = DataIntegrityProof.verify(AttestationTimestamps.withoutTimestamps(attestation, attestationIri), attestationIri);
        problems.addAll(sig.problems());
        if ( expectedKey.isPresent() && sig.verificationMethod() != null
             && !sig.verificationMethod().startsWith(expectedKey.get() + "#") )
            problems.add("Signed by " + sig.verificationMethod() + ", expected " + expectedKey.get());

        // 1b. RFC 3161 timestamps over the signature
        List<AttestationTimestamps.Check> timestamps = AttestationTimestamps.verify(attestation, attestationIri, options.tsaTrustAnchors());
        for ( AttestationTimestamps.Check c : timestamps )
            c.token().problems().forEach(p -> problems.add("Timestamp" + (c.authority() == null ? "" : " from " + c.authority()) + ": " + p));
        if ( options.requireTimestamp() && timestamps.stream().noneMatch(c -> c.token().acceptable()) )
            problems.add(timestamps.isEmpty() ? "No RFC 3161 timestamp, and one is required"
                                              : "No valid, trusted RFC 3161 timestamp, and one is required");

        // 2. Claims
        Node result = object(attestation, attestationIri, Vocab.attests);
        if ( result == null )
            return new Report(attestationIri, sig.valid(), false, sig.verificationMethod(), -1, null, -1, 0, Optional.empty(), timestamps,
                              add(problems, "No jip:attests"));
        TreeSet<String> vars = new TreeSet<>();
        attestation.find(result, Vocab.variable, Node.ANY).forEach(t -> vars.add(t.getObject().getLiteralLexicalForm()));
        boolean ordered = "true".equals(lexical(attestation, result, Vocab.ordered));
        int count = Integer.parseInt(lexical(attestation, result, Vocab.solutionCount));
        String digest = lexical(attestation, result, Vocab.digest);
        Node state = object(attestation, result, Vocab.provWasDerivedFrom);
        Node exec = object(attestation, result, Vocab.provWasGeneratedBy);
        Optional<Requester> requester = exec == null ? Optional.empty() : Requester.from(attestation, exec);
        String versionLex = state == null ? null : lexical(attestation, state, Vocab.dataVersion);
        long version = versionLex == null ? -1 : Long.parseLong(versionLex);

        for ( String v : vars ) {
            if ( !resultVars.contains(v) )
                problems.add("Result does not include attested variable ?" + v + " (project it in the outer query)");
        }

        // 3. Rows of this attestation
        List<Binding> mine = rows.stream().filter(b -> carries(b, attestationIri)).toList();
        List<Binding> attested;
        if ( count == 0 ) {
            attested = List.of();
            boolean markerOnly = mine.size() == 1 && vars.stream().noneMatch(v -> mine.get(0).contains(Var.alloc(v)));
            if ( !mine.isEmpty() && !markerOnly )
                problems.add("Attestation says 0 solutions but " + mine.size() + " row(s) carry data");
        } else {
            attested = mine;
            if ( mine.size() != count )
                problems.add("Attestation says " + count + " solution(s), result has " + mine.size() + " row(s) with this attestation");
        }
        String actual = ResultSetEncoding.digest(vars, attested, ordered);
        boolean digestOk = actual.equals(digest);
        if ( !digestOk )
            problems.add("Result digest mismatch: attestation " + digest + ", rows " + actual);

        return new Report(attestationIri, sig.valid(), digestOk, sig.verificationMethod(), version, state, count, mine.size(), requester, timestamps,
                          List.copyOf(problems));
    }

    /**
     * Parse an attestation file. The syntax comes from the file extension (Turtle if it is not
     * recognized).
     */
    public static Graph readAttestation(Path file) {
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
     * CSV loses term types, so attestations verify reliably only against JSON, XML or TSV.
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

    private static boolean carries(Binding b, Node attestationIri) {
        for ( var it = b.vars() ; it.hasNext() ; ) {
            if ( attestationIri.equals(b.get(it.next())) )
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
