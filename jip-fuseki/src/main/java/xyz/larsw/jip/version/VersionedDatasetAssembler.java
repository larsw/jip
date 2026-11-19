package xyz.larsw.jip.version;

import java.nio.file.Path;

import org.apache.jena.assembler.Assembler;
import org.apache.jena.assembler.exceptions.AssemblerException;
import org.apache.jena.dboe.base.file.Location;
import org.apache.jena.rdf.model.RDFNode;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.rdf.model.Statement;
import org.apache.jena.sparql.core.DatasetGraph;
import org.apache.jena.sparql.core.assembler.DatasetAssembler;
import org.apache.jena.sparql.util.graph.GraphUtils;
import org.apache.jena.tdb2.assembler.DatasetAssemblerTDB2;
import org.apache.jena.tdb2.assembler.VocabTDB2;
import xyz.larsw.jip.JIP;

/**
 * Assembler for {@code jip:VersionedDatasetTDB2}: a TDB2 dataset with the persistent data
 * version attached.
 *
 * <pre>
 * :ds a jip:VersionedDatasetTDB2 ;
 *     tdb2:location "/fuseki/databases/ds" ;
 *     jip:datasetIRI &lt;https://example.org/ds&gt; ;   # optional
 *     tdb2:unionDefaultGraph true .                  # optional, passed to TDB2
 * </pre>
 *
 * Steps: replay the data version from the journal ({@link PreOpenJournalRecovery}) before the
 * database is opened, open it with the standard TDB2 assembler, attach the component. The
 * returned dataset is the plain TDB2 container, so compaction/backup/stats keep working.
 */
public class VersionedDatasetAssembler extends DatasetAssembler {

    @Override
    public DatasetGraph createDataset(Assembler a, Resource root) {
        if ( !GraphUtils.exactlyOneProperty(root, VocabTDB2.pLocation) )
            throw new AssemblerException(root, "Exactly one tdb2:location required");
        String dir = GraphUtils.getAsFilename(root, VocabTDB2.pLocation);
        Location location = Location.create(dir);

        String datasetIRI = null;
        Statement s = root.getProperty(JIP.datasetIRI);
        if ( s != null ) {
            RDFNode n = s.getObject();
            if ( n.isURIResource() )
                datasetIRI = n.asResource().getURI();
            else if ( n.isLiteral() )
                datasetIRI = n.asLiteral().getLexicalForm();
            else
                throw new AssemblerException(root, "jip:datasetIRI must be an IRI");
        }

        if ( !location.isMem() && !DataVersion.isAttached(location) )
            PreOpenJournalRecovery.recover(Path.of(location.getDirectoryPath()));

        DatasetGraph dsg = DatasetAssemblerTDB2.make(a, root);
        DataVersion.attach(dsg, datasetIRI);
        return dsg;
    }
}
