package org.example.jena.provenance.cli;

import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.Optional;

import org.apache.jena.sys.JenaSystem;
import org.example.jena.provenance.cert.CertificateVerifier;

/**
 * Independent verification of a certified SPARQL result.
 *
 * <pre>
 * java -jar jip-verify.jar --results results.srj --cert certificate.ttl [--expect-key did:key:z6Mk...]
 * </pre>
 *
 * Exit status: 0 valid, 1 invalid, 2 usage or input error. The checks are in
 * {@link CertificateVerifier}; this class only parses arguments and prints the report.
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
            switch (a) {
                case "--results", "-r", "--cert", "-c", "--expect-key", "-k" -> {
                    String value = i + 1 < args.length ? args[i + 1] : null;
                    // A following option is a forgotten value, not a file; write ./-name for a
                    // file whose name starts with '-'.
                    if ( value == null || value.isEmpty() || value.startsWith("-") )
                        return usageError("Missing value for " + a);
                    i++;
                    try {
                        switch (a) {
                            case "--results", "-r" -> results = Path.of(value);
                            case "--cert", "-c" -> cert = Path.of(value);
                            default -> expectKey = value;
                        }
                    } catch (InvalidPathException ex) {
                        return usageError("Bad file name for " + a + ": " + ex.getMessage());
                    }
                }
                case "--help", "-h" -> { usage(); return 0; }
                default -> { return usageError("Unknown argument: " + a); }
            }
        }
        if ( results == null )
            return usageError("Missing --results");
        if ( cert == null )
            return usageError("Missing --cert");
        JenaSystem.init();
        try {
            CertificateVerifier.Report report = CertificateVerifier.verify(cert, results, Optional.ofNullable(expectKey));
            print(report);
            return report.valid() ? 0 : 1;
        } catch (Exception ex) {
            System.err.println("Error: " + ex.getMessage());
            return 2;
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

    private static int usageError(String message) {
        System.err.println("Error: " + message);
        usage();
        return 2;
    }

    private static void usage() {
        System.err.println("""
                Usage: verify --results <results.srj|.srx|.tsv> --cert <certificate.ttl|.jsonld|.nt> [--expect-key did:key:...]
                  Verifies the eddsa-rdfc-2022 proof of a result certificate and that the rows carrying the
                  certificate IRI match its RDFC-1.0 digest. Exit: 0 valid, 1 invalid, 2 error.""");
    }
}
