package xyz.larsw.jip.canon;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.jena.graph.Node;
import org.apache.jena.graph.NodeFactory;
import org.apache.jena.graph.Triple;
import org.apache.jena.sparql.core.Var;
import org.apache.jena.sparql.engine.binding.Binding;
import org.apache.jena.sparql.engine.binding.BindingBuilder;
import org.apache.jena.sparql.util.NodeFactoryExtra;
import org.junit.jupiter.api.Test;

class ResultSetEncodingTest {

    static final List<String> VARS = List.of("s", "name");

    static Binding row(Node s, Node name) {
        BindingBuilder b = BindingBuilder.create();
        if ( s != null )
            b.add(Var.alloc("s"), s);
        if ( name != null )
            b.add(Var.alloc("name"), name);
        return b.build();
    }

    static Node iri(String x) {
        return NodeFactory.createURI("http://example.org/" + x);
    }

    static Node lit(String x) {
        return NodeFactory.createLiteralString(x);
    }

    static List<Binding> rows() {
        return List.of(row(iri("a"), lit("Alice")), row(iri("b"), lit("Bob")), row(iri("c"), null));
    }

    @Test
    void unorderedDigestIgnoresRowOrder() {
        List<Binding> reversed = new ArrayList<>(rows());
        Collections.reverse(reversed);
        assertEquals(ResultSetEncoding.digest(VARS, rows(), false), ResultSetEncoding.digest(VARS, reversed, false));
    }

    @Test
    void orderedDigestDependsOnRowOrder() {
        List<Binding> reversed = new ArrayList<>(rows());
        Collections.reverse(reversed);
        assertNotEquals(ResultSetEncoding.digest(VARS, rows(), true), ResultSetEncoding.digest(VARS, reversed, true));
        assertNotEquals(ResultSetEncoding.digest(VARS, rows(), true), ResultSetEncoding.digest(VARS, rows(), false));
    }

    @Test
    void anyValueChangeChangesDigest() {
        List<Binding> changed = List.of(row(iri("a"), lit("Alice")), row(iri("b"), lit("Bobby")), row(iri("c"), null));
        assertNotEquals(ResultSetEncoding.digest(VARS, rows(), false), ResultSetEncoding.digest(VARS, changed, false));
        List<Binding> typed = List.of(row(iri("a"), lit("Alice")), row(iri("b"), NodeFactory.createLiteralLang("Bob", "en")),
                                      row(iri("c"), null));
        assertNotEquals(ResultSetEncoding.digest(VARS, rows(), false), ResultSetEncoding.digest(VARS, typed, false));
    }

    @Test
    void duplicatesAreCounted() {
        List<Binding> once = List.of(row(iri("a"), lit("Alice")));
        List<Binding> twice = List.of(row(iri("a"), lit("Alice")), row(iri("a"), lit("Alice")));
        assertNotEquals(ResultSetEncoding.digest(VARS, once, false), ResultSetEncoding.digest(VARS, twice, false));
    }

    @Test
    void blankNodeLabelsDoNotMatterButCoreferenceDoes() {
        Node b1 = NodeFactory.createBlankNode("x1");
        Node b2 = NodeFactory.createBlankNode("y2");
        Node b3 = NodeFactory.createBlankNode("z3");
        // Same bnode in two rows vs. renamed (still shared): equal.
        String shared1 = ResultSetEncoding.digest(VARS, List.of(row(b1, lit("A")), row(b1, lit("B"))), false);
        String shared2 = ResultSetEncoding.digest(VARS, List.of(row(b2, lit("A")), row(b2, lit("B"))), false);
        assertEquals(shared1, shared2);
        // Two different bnodes: not equal to the shared case.
        String distinct = ResultSetEncoding.digest(VARS, List.of(row(b2, lit("A")), row(b3, lit("B"))), false);
        assertNotEquals(shared1, distinct);
    }

    @Test
    void emptyResultHasStableDigest() {
        assertEquals(ResultSetEncoding.digest(VARS, List.of(), false), ResultSetEncoding.digest(List.of("name", "s"), List.of(), false));
    }

    @Test
    void rejectsRdf12Terms() {
        Node tripleTerm = NodeFactory.createTripleTerm(Triple.create(iri("a"), iri("p"), iri("b")));
        assertThrows(RdfCanonicalizer.UnsupportedTermException.class,
                     () -> ResultSetEncoding.digest(VARS, List.of(row(iri("a"), tripleTerm)), false));
        Node directional = NodeFactoryExtra.parseNode("\"hello\"@en--ltr");
        assertThrows(RdfCanonicalizer.UnsupportedTermException.class,
                     () -> ResultSetEncoding.digest(VARS, List.of(row(iri("a"), directional)), false));
    }
}
