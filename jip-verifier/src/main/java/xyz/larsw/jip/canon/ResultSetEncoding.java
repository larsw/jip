package xyz.larsw.jip.canon;

import java.util.Collection;
import java.util.List;

import org.apache.jena.datatypes.xsd.XSDDatatype;
import org.apache.jena.graph.Graph;
import org.apache.jena.graph.Node;
import org.apache.jena.graph.NodeFactory;
import org.apache.jena.graph.GraphMemFactory;
import org.apache.jena.sparql.core.Var;
import org.apache.jena.sparql.engine.binding.Binding;
import org.apache.jena.vocabulary.RDF;

/**
 * Encodes a SPARQL solution sequence as RDF with the W3C result-set vocabulary, so it can be
 * canonicalized with RDFC-1.0 and hashed.
 *
 * <pre>
 * _:R a rs:ResultSet ;
 *     rs:resultVariable "v" ;              # each certified variable
 *     rs:solution _:S1 , ... .
 * _:Si rs:index i .                        # only if ordered (1-based)
 * _:Si rs:binding _:B .
 * _:B  rs:variable "v" ; rs:value term .   # bound certified variables only
 * </pre>
 *
 * Blank node values keep their identity: the same blank node in two rows is the same RDF
 * blank node. Duplicate solutions stay distinct (each solution is its own blank node).
 * Without {@code rs:index} the encoding (and so the digest) does not depend on row order.
 */
public final class ResultSetEncoding {
    private ResultSetEncoding() {}

    public static final String RS = "http://www.w3.org/2001/sw/DataAccess/tests/result-set#";
    public static final Node ResultSet = NodeFactory.createURI(RS + "ResultSet");
    public static final Node resultVariable = NodeFactory.createURI(RS + "resultVariable");
    public static final Node solution = NodeFactory.createURI(RS + "solution");
    public static final Node index = NodeFactory.createURI(RS + "index");
    public static final Node binding = NodeFactory.createURI(RS + "binding");
    public static final Node variable = NodeFactory.createURI(RS + "variable");
    public static final Node value = NodeFactory.createURI(RS + "value");

    /**
     * Encode the rows.
     *
     * @param variables certified variable names (without '?'); other variables in the rows are ignored
     * @param rows      the solutions, in delivery order
     * @param ordered   add {@code rs:index} to each solution
     */
    public static Graph encode(Collection<String> variables, List<Binding> rows, boolean ordered) {
        Graph g = GraphMemFactory.createDefaultGraph();
        Node rs = NodeFactory.createBlankNode();
        g.add(rs, RDF.type.asNode(), ResultSet);
        for ( String v : variables )
            g.add(rs, resultVariable, NodeFactory.createLiteralString(v));
        int i = 0;
        for ( Binding row : rows ) {
            i++;
            Node s = NodeFactory.createBlankNode();
            g.add(rs, solution, s);
            if ( ordered )
                g.add(s, index, NodeFactory.createLiteralDT(Integer.toString(i), XSDDatatype.XSDinteger));
            for ( String v : variables ) {
                Node term = row.get(Var.alloc(v));
                if ( term == null )
                    continue;
                Node b = NodeFactory.createBlankNode();
                g.add(s, binding, b);
                g.add(b, variable, NodeFactory.createLiteralString(v));
                g.add(b, value, term);
            }
        }
        return g;
    }

    /** RDFC-1.0 canonical N-Quads of the encoding. */
    public static String canonical(Collection<String> variables, List<Binding> rows, boolean ordered) {
        return RdfCanonicalizer.standard().canonicalize(encode(variables, rows, ordered));
    }

    /** SHA-256 (hex) of the canonical N-Quads of the encoding. */
    public static String digest(Collection<String> variables, List<Binding> rows, boolean ordered) {
        return RdfCanonicalizer.sha256Hex(canonical(variables, rows, ordered));
    }
}
