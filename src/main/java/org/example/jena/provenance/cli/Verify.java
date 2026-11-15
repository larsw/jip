package org.example.jena.provenance.cli;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.apache.jena.graph.Graph;
import org.apache.jena.graph.GraphMemFactory;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFLanguages;
import org.apache.jena.riot.RDFParser;
import org.apache.jena.riot.ResultSetMgr;
import org.apache.jena.riot.resultset.ResultSetLang;
import org.apache.jena.riot.system.ErrorHandlerFactory;
import org.apache.jena.sparql.engine.binding.Binding;
import org.apache.jena.sparql.exec.RowSet;
import org.apache.jena.sys.JenaSystem;
import org.example.jena.provenance.cert.CertificateVerifier;

/**
 * Independent verification of a certified SPARQL result.
 *
 * <pre>
 * verify --results results.srj --cert certificate.ttl [--expect-key did:key:z6Mk...]
 * </pre>
 *
 * Exit status: 0 valid, 1 invalid, 2 usage or input error.
 */
public final class Verify {
    private Verify() {}

    public static void main(String... args) {
        System.exit(run(args));
    }

    public static int run(String... args) {
        Path results = null;
        Path cert = null;
        String expectKey = null;
        for ( int i = 0 ; i < args.length ; i++ ) {
            String a = args[i];
            String next = i + 1 < args.length ? args[i + 1] : null;
            switch (a) {
                case "--results", "-r" -> { results = path(next); i++; }
                case "--cert", "-c" -> { cert = path(next); i++; }
                case "--expect-key", "-k" -> { expectKey = next; i++; }
                case "--help", "-h" -> { usage(); return 0; }
                default -> { System.err.println("Unknown argument: " + a); usage(); return 2; }
            }
        }
        if ( results == null || cert == null ) {
            usage();
            return 2;
        }
        JenaSystem.init();
        try {
            Graph certificate = readCertificate(cert);
            List<String> vars = new ArrayList<>();
            List<Binding> rows = new ArrayList<>();
            readResults(results, vars, rows);

            CertificateVerifier.Report report = CertificateVerifier.verify(certificate, vars, rows, Optional.ofNullable(expectKey));
            print(report);
            return report.valid() ? 0 : 1;
        } catch (Exception ex) {
            System.err.println("Error: " + ex.getMessage());
            return 2;
        }
    }

    static Graph readCertificate(Path file) {
        Lang lang = RDFLanguages.pathnameToLang(file.toString());
        Graph g = GraphMemFactory.createDefaultGraph();
        // Jena's IRI checker warns about the '#' in did:key verification method IRIs, which
        // DID URL syntax allows; the warning is noise here.
        RDFParser.source(file).lang(lang == null ? Lang.TURTLE : lang)
                .errorHandler(ErrorHandlerFactory.errorHandlerNoWarnings)
                .parse(g);
        return g;
    }

    static void readResults(Path file, List<String> vars, List<Binding> rows) throws Exception {
        String name = file.getFileName().toString().toLowerCase();
        Lang lang = name.endsWith(".srx") || name.endsWith(".xml") ? ResultSetLang.RS_XML
                : name.endsWith(".tsv") ? ResultSetLang.RS_TSV
                : name.endsWith(".csv") ? ResultSetLang.RS_CSV
                : ResultSetLang.RS_JSON;
        try ( InputStream in = Files.newInputStream(file) ) {
            RowSet rs = RowSet.adapt(ResultSetMgr.read(in, lang));
            rs.getResultVars().forEach(v -> vars.add(v.getVarName()));
            rs.forEachRemaining(rows::add);
        }
    }

    private static void print(CertificateVerifier.Report r) {
        System.out.println("Certificate     : " + (r.certificate() == null ? "(none)" : r.certificate().getURI()));
        System.out.println("Signed by       : " + r.verificationMethod());
        System.out.println("Signature       : " + (r.signatureValid() ? "OK" : "INVALID"));
        System.out.println("Dataset state   : " + (r.datasetState() == null ? "?" : r.datasetState().getURI()) + "  (version "
                           + r.dataVersion() + ")");
        System.out.println("Solutions       : " + r.solutionCount() + " certified, " + r.rowsChecked() + " row(s) carry this certificate");
        System.out.println("Result digest   : " + (r.digestValid() ? "OK" : "MISMATCH"));
        for ( String p : r.problems() )
            System.out.println("Problem         : " + p);
        System.out.println(r.valid() ? "VERIFIED" : "NOT VERIFIED");
    }

    private static Path path(String s) {
        if ( s == null )
            throw new IllegalArgumentException("Missing file argument");
        return Path.of(s);
    }

    private static void usage() {
        System.err.println("""
                Usage: verify --results <results.srj|.srx|.tsv> --cert <certificate.ttl|.jsonld|.nt> [--expect-key did:key:...]
                  Verifies the eddsa-rdfc-2022 proof of a result certificate and that the rows carrying the
                  certificate IRI match its RDFC-1.0 digest. Exit: 0 valid, 1 invalid, 2 error.""");
    }
}
