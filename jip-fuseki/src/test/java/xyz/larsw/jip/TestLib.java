package xyz.larsw.jip;

import org.apache.jena.query.DatasetFactory;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFParser;
import org.apache.jena.sparql.core.DatasetGraph;

/** Shared test helpers. */
public final class TestLib {
    private TestLib() {}

    /** Build a dataset through the jip:VersionedDatasetTDB2 assembler. */
    public static DatasetGraph assembleVersioned(String location) {
        String ttl = """
                PREFIX jip:  <https://larsw.xyz/jip/>
                PREFIX tdb2: <http://jena.apache.org/2016/tdb#>
                <urn:ex:ds> a jip:VersionedDatasetTDB2 ;
                    tdb2:location "%s" ;
                    jip:datasetIRI <https://example.org/ds> .
                """.formatted(location);
        Model m = ModelFactory.createDefaultModel();
        RDFParser.fromString(ttl, Lang.TTL).parse(m);
        return DatasetFactory.assemble(m.getResource("urn:ex:ds")).asDatasetGraph();
    }
}
