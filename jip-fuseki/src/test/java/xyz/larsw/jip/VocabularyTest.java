package xyz.larsw.jip;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.file.Path;
import java.util.Set;
import java.util.TreeSet;

import org.apache.jena.graph.Node;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFParser;
import org.apache.jena.sparql.util.Symbol;
import org.apache.jena.vocabulary.OWL;
import org.apache.jena.vocabulary.RDF;
import org.apache.jena.vocabulary.RDFS;
import xyz.larsw.jip.cert.Vocab;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** Keeps vocab/jip.ttl in step with the jip: terms the code uses. */
public class VocabularyTest {

    static final Path FILE = Path.of("..", "vocab", "jip.ttl");   // tests run in jip-fuseki/
    /** Slash namespace: the ontology IRI is the namespace IRI. */
    static final String ONTOLOGY = JIP.NS;
    static Model vocab;

    @BeforeAll
    static void load() {
        vocab = ModelFactory.createDefaultModel();
        RDFParser.source(FILE).lang(Lang.TURTLE).strict(true).parse(vocab);
    }

    /** All jip: IRIs defined as constants in JIP and Vocab. */
    static Set<String> termsInCode() throws IllegalAccessException {
        Set<String> terms = new TreeSet<>();
        for ( Class<?> c : new Class<?>[] {JIP.class, Vocab.class} ) {
            for ( Field f : c.getDeclaredFields() ) {
                if ( !Modifier.isStatic(f.getModifiers()) || !Modifier.isPublic(f.getModifiers()) )
                    continue;
                Object v = f.get(null);
                String iri = switch (v) {
                    case Node n when n.isURI() -> n.getURI();
                    case Resource r when r.isURIResource() -> r.getURI();
                    case Symbol s -> s.getSymbol();
                    case String s -> s;
                    default -> null;
                };
                if ( iri != null && iri.startsWith(JIP.NS) && iri.length() > JIP.NS.length() )
                    terms.add(iri);
            }
        }
        return terms;
    }

    static Set<String> termsInFile() {
        Set<String> terms = new TreeSet<>();
        vocab.listSubjects().forEachRemaining(s -> {
            if ( s.isURIResource() && s.getURI().startsWith(JIP.NS) && !s.getURI().equals(ONTOLOGY) )
                terms.add(s.getURI());
        });
        return terms;
    }

    @Test
    void declaresTheOntology() {
        Resource ontology = vocab.createResource(ONTOLOGY);
        assertTrue(vocab.contains(ontology, RDF.type, OWL.Ontology), "owl:Ontology <" + ONTOLOGY + ">");
        assertEquals(JIP.NS, ontology.getProperty(vocab.createProperty("http://purl.org/vocab/vann/preferredNamespaceUri"))
                .getString());
    }

    @Test
    void definesEveryTermTheCodeUses() throws IllegalAccessException {
        Set<String> missing = new TreeSet<>(termsInCode());
        missing.removeAll(termsInFile());
        assertTrue(missing.isEmpty(), "Not defined in " + FILE + ": " + missing);

        for ( String iri : termsInCode() ) {
            Resource term = vocab.createResource(iri);
            assertTrue(term.hasProperty(RDF.type), iri + " has no rdf:type");
            assertTrue(term.hasProperty(RDFS.label), iri + " has no rdfs:label");
            assertTrue(term.hasProperty(RDFS.comment), iri + " has no rdfs:comment");
            assertTrue(term.hasProperty(RDFS.isDefinedBy, vocab.createResource(ONTOLOGY)), iri + " has no rdfs:isDefinedBy");
        }
    }

    @Test
    void definesNoUnusedTerms() throws IllegalAccessException {
        Set<String> unused = new TreeSet<>(termsInFile());
        unused.removeAll(termsInCode());
        assertTrue(unused.isEmpty(), "Defined in " + FILE + " but not used by the code: " + unused);
    }
}
