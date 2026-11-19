package xyz.larsw.jip.canon;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.Map;
import java.util.function.Function;

import org.apache.jena.graph.Graph;
import org.apache.jena.graph.Node;
import org.apache.jena.graph.Triple;
import org.apache.jena.sparql.core.DatasetGraph;
import org.apache.jena.sparql.core.Quad;
import org.apache.jena.vocabulary.RDF;

import com.apicatalog.rdf.canon.RdfCanon;
import com.apicatalog.rdf.canon.RdfCanonTicker;
import com.apicatalog.rdf.canon.RdfCanonTimeTicker;

/**
 * RDF Dataset Canonicalization (RDFC-1.0, https://www.w3.org/TR/rdf-canon/) for Jena data,
 * using the titanium-rdfc implementation.
 * <p>
 * Only RDF 1.1 terms are supported: triple terms and literals with a base direction are
 * rejected with {@link UnsupportedTermException}, because RDFC-1.0 does not define them.
 * <p>
 * Canonicalization is bounded by a time limit (default 10 s) to defend against "poison"
 * graphs whose blank node structure makes the algorithm explode.
 */
public final class RdfCanonicalizer {

    /** Default limit on the time spent canonicalizing one dataset. */
    public static final long DEFAULT_TIME_LIMIT_MILLIS = 10_000;

    /** Thrown for terms outside RDF 1.1 (triple terms, directional literals). */
    public static class UnsupportedTermException extends RuntimeException {
        public UnsupportedTermException(String msg) {
            super(msg);
        }
    }

    /** Canonical N-Quads plus the blank node mapping (input label → canonical label). */
    public record Result(String canonicalNQuads, Map<String, String> blankNodeMapping) {}

    private final String hashAlgorithm;
    private final long timeLimitMillis;
    private final boolean labelsAsGiven;

    private RdfCanonicalizer(String hashAlgorithm, long timeLimitMillis, boolean labelsAsGiven) {
        this.hashAlgorithm = hashAlgorithm;
        this.timeLimitMillis = timeLimitMillis;
        this.labelsAsGiven = labelsAsGiven;
    }

    /** RDFC-1.0 with SHA-256 and the default time limit. */
    public static RdfCanonicalizer standard() {
        return new RdfCanonicalizer("SHA-256", DEFAULT_TIME_LIMIT_MILLIS, false);
    }

    /**
     * Fully configured instance.
     *
     * @param hashAlgorithm   "SHA-256" or "SHA-384" (the RDFC-1.0 internal hash)
     * @param timeLimitMillis abort canonicalization after this time
     * @param labelsAsGiven   use Jena's blank node labels as input identifiers (for the W3C map
     *                        tests); otherwise labels are assigned sequentially
     */
    public static RdfCanonicalizer create(String hashAlgorithm, long timeLimitMillis, boolean labelsAsGiven) {
        return new RdfCanonicalizer(hashAlgorithm, timeLimitMillis, labelsAsGiven);
    }

    public String canonicalize(DatasetGraph dsg) {
        return canonicalizeWithMapping(dsg.find()).canonicalNQuads();
    }

    public String canonicalize(Graph graph) {
        Iterator<Triple> iter = graph.find();
        Iterator<Quad> quads = new Iterator<>() {
            @Override
            public boolean hasNext() {
                return iter.hasNext();
            }

            @Override
            public Quad next() {
                return Quad.create(Quad.defaultGraphNodeGenerated, iter.next());
            }
        };
        return canonicalizeWithMapping(quads).canonicalNQuads();
    }

    public String canonicalize(Iterator<Quad> quads) {
        return canonicalizeWithMapping(quads).canonicalNQuads();
    }

    /**
     * Canonicalize the quads.
     *
     * @throws UnsupportedTermException for RDF 1.2 terms
     * @throws IllegalStateException    if the time limit is exceeded
     */
    public Result canonicalizeWithMapping(Iterator<Quad> quads) {
        RdfCanonTicker ticker = new RdfCanonTimeTicker(timeLimitMillis);
        RdfCanon canon = RdfCanon.create(hashAlgorithm, ticker);
        Function<Node, String> labels = blankLabeller();
        while ( quads.hasNext() ) {
            Quad q = quads.next();
            Node o = q.getObject();
            String graph = q.isDefaultGraph() ? null : resource(q.getGraph(), labels);
            String subject = resource(q.getSubject(), labels);
            String predicate = iri(q.getPredicate());
            if ( o.isLiteral() ) {
                if ( o.getLiteralBaseDirection() != null )
                    throw new UnsupportedTermException("Literal with base direction (RDF 1.2) is not supported by RDFC-1.0: " + o);
                String lang = o.getLiteralLanguage();
                boolean hasLang = lang != null && !lang.isEmpty();
                String datatype = hasLang ? RDF.dtLangString.getURI() : o.getLiteralDatatypeURI();
                canon.quad(subject, predicate, o.getLiteralLexicalForm(), datatype, hasLang ? lang : null, null, graph);
            } else {
                canon.quad(subject, predicate, resource(o, labels), null, null, null, graph);
            }
        }
        StringBuilder sb = new StringBuilder();
        canon.provide(sb::append);
        return new Result(sb.toString(), canon.mapping());
    }

    /** SHA-256 of the UTF-8 bytes of a string, as lowercase hex. */
    public static String sha256Hex(String text) {
        return HexFormat.of().formatHex(sha256(text));
    }

    public static byte[] sha256(String text) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private Function<Node, String> blankLabeller() {
        if ( labelsAsGiven )
            return n -> "_:" + n.getBlankNodeLabel();
        Map<Node, String> assigned = new HashMap<>();
        return n -> assigned.computeIfAbsent(n, x -> "_:b" + assigned.size());
    }

    private static String resource(Node n, Function<Node, String> labels) {
        if ( n.isBlank() )
            return labels.apply(n);
        return iri(n);
    }

    private static String iri(Node n) {
        if ( n.isURI() )
            return n.getURI();
        if ( n.isTripleTerm() )
            throw new UnsupportedTermException("Triple term (RDF 1.2) is not supported by RDFC-1.0: " + n);
        throw new UnsupportedTermException("Unexpected RDF term in this position: " + n);
    }
}
