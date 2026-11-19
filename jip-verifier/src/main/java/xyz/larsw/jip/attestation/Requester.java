package xyz.larsw.jip.attestation;

import java.util.Optional;

import org.apache.jena.graph.Graph;
import org.apache.jena.graph.Node;
import org.apache.jena.graph.NodeFactory;
import org.apache.jena.graph.Triple;
import org.apache.jena.vocabulary.RDF;

/**
 * The authenticated user who asked for an attestation, as the server saw it: the principal name
 * and, if known, the HTTP authentication scheme ({@code BASIC}, {@code DIGEST}, {@code BEARER},
 * ...). In an attestation the requester is a {@code prov:Agent} associated with the query
 * execution in the role {@code jip:requester}:
 * <pre>
 * &lt;A#exec&gt; prov:wasAssociatedWith &lt;A#requester&gt; ;
 *     prov:qualifiedAssociation [ a prov:Association ; prov:agent &lt;A#requester&gt; ; prov:hadRole jip:requester ] .
 * &lt;A#requester&gt; a prov:Agent ; jip:principal "alice" ; jip:authenticationScheme "BASIC" .
 * </pre>
 * The statement is part of the signed document: the signing server vouches that it
 * authenticated this principal. It says nothing about how strong that authentication was.
 */
public record Requester(String principal, String scheme) {
    public Requester {
        if ( principal == null || principal.isBlank() )
            throw new IllegalArgumentException("Requester needs a principal name");
        scheme = scheme == null || scheme.isBlank() ? null : scheme;
    }

    /** Add the requester to an attestation graph, associated with the query execution {@code exec}. */
    public Node addTo(Graph g, Node exec) {
        Node agent = NodeFactory.createURI(exec.getURI().replaceFirst("#exec$", "") + "#requester");
        Node association = NodeFactory.createBlankNode();
        Node type = RDF.type.asNode();
        g.add(exec, Vocab.provWasAssociatedWith, agent);
        g.add(exec, Vocab.provQualifiedAssociation, association);
        g.add(association, type, Vocab.provAssociation);
        g.add(association, Vocab.provAgentProperty, agent);
        g.add(association, Vocab.provHadRole, Vocab.requester);
        g.add(agent, type, Vocab.provAgent);
        g.add(agent, Vocab.principal, NodeFactory.createLiteralString(principal));
        if ( scheme != null )
            g.add(agent, Vocab.authenticationScheme, NodeFactory.createLiteralString(scheme));
        return agent;
    }

    /** The requester recorded for the query execution {@code exec}, if any. */
    public static Optional<Requester> from(Graph g, Node exec) {
        for ( Triple qa : g.find(exec, Vocab.provQualifiedAssociation, Node.ANY).toList() ) {
            Node association = qa.getObject();
            if ( !g.contains(association, Vocab.provHadRole, Vocab.requester) )
                continue;
            for ( Triple a : g.find(association, Vocab.provAgentProperty, Node.ANY).toList() ) {
                Optional<String> name = literal(g, a.getObject(), Vocab.principal);
                if ( name.isPresent() )
                    return Optional.of(new Requester(name.get(), literal(g, a.getObject(), Vocab.authenticationScheme).orElse(null)));
            }
        }
        return Optional.empty();
    }

    private static Optional<String> literal(Graph g, Node s, Node p) {
        var it = g.find(s, p, Node.ANY);
        while ( it.hasNext() ) {
            Node o = it.next().getObject();
            if ( o.isLiteral() )
                return Optional.of(o.getLiteralLexicalForm());
        }
        return Optional.empty();
    }

    @Override
    public String toString() {
        return scheme == null ? principal : principal + " (" + scheme + ")";
    }
}
