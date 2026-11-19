package xyz.larsw.jip.cli;

import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.security.cert.TrustAnchor;
import java.util.Optional;
import java.util.Set;

import org.apache.jena.sys.JenaSystem;
import xyz.larsw.jip.attestation.AttestationTimestamps;
import xyz.larsw.jip.attestation.AttestationVerifier;
import xyz.larsw.jip.attestation.Requester;
import xyz.larsw.jip.attestation.Rfc3161;
import xyz.larsw.jip.attestation.TrustedKeys;

/**
 * Independent verification of an attested SPARQL result.
 *
 * <pre>
 * java -jar jip-verify.jar --results results.srj --attestation attestation.ttl
 *                          [--expect-key did:key:zDn...]... [--trusted-keys keys.json]...
 *                          [--tsa-trust system|none|anchors.pem] [--require-timestamp]
 * </pre>
 *
 * Exit status: 0 valid, 1 invalid, 2 usage or input error. The checks are in
 * {@link AttestationVerifier}; this class only parses arguments and prints the report.
 */
public final class Verify {
    private Verify() {}

    public static void main(String... args) {
        System.exit(run(args));
    }

    public static int run(String... args) {
        Path results = null;
        Path attestationFile = null;
        java.util.List<String> expectKeys = new java.util.ArrayList<>();
        java.util.List<Path> trustedKeyFiles = new java.util.ArrayList<>();
        String tsaTrust = "system";
        boolean requireTimestamp = false;
        for ( int i = 0 ; i < args.length ; i++ ) {
            String a = args[i];
            switch (a) {
                case "--results", "-r", "--attestation", "-a", "--expect-key", "-k", "--trusted-keys", "--tsa-trust" -> {
                    String value = i + 1 < args.length ? args[i + 1] : null;
                    // A following option is a forgotten value, not a file; write ./-name for a
                    // file whose name starts with '-'.
                    if ( value == null || value.isEmpty() || value.startsWith("-") )
                        return usageError("Missing value for " + a);
                    i++;
                    try {
                        switch (a) {
                            case "--results", "-r" -> results = Path.of(value);
                            case "--attestation", "-a" -> attestationFile = Path.of(value);
                            case "--tsa-trust" -> tsaTrust = value;
                            case "--trusted-keys" -> trustedKeyFiles.add(Path.of(value));
                            default -> expectKeys.add(value);
                        }
                    } catch (InvalidPathException ex) {
                        return usageError("Bad file name for " + a + ": " + ex.getMessage());
                    }
                }
                case "--require-timestamp" -> requireTimestamp = true;
                case "--help", "-h" -> { usage(); return 0; }
                default -> { return usageError("Unknown argument: " + a); }
            }
        }
        if ( results == null )
            return usageError("Missing --results");
        if ( attestationFile == null )
            return usageError("Missing --attestation");
        JenaSystem.init();
        try {
            Optional<Set<TrustAnchor>> anchors = switch (tsaTrust) {
                case "system" -> Optional.of(Rfc3161.systemTrustAnchors());
                case "none" -> Optional.empty();
                default -> Optional.of(Rfc3161.trustAnchors(Path.of(tsaTrust)));
            };
            Set<String> trusted = new java.util.LinkedHashSet<>(expectKeys);
            for ( Path f : trustedKeyFiles )
                trusted.addAll(TrustedKeys.fromJwkSet(f));
            AttestationVerifier.Options options = new AttestationVerifier.Options(trusted, anchors, requireTimestamp);
            AttestationVerifier.Report report = AttestationVerifier.verify(attestationFile, results, options);
            print(report);
            return report.valid() ? 0 : 1;
        } catch (Exception ex) {
            System.err.println("Error: " + ex.getMessage());
            return 2;
        }
    }

    private static void print(AttestationVerifier.Report r) {
        System.out.println("Attestation     : " + (r.attestation() == null ? "(none)" : r.attestation().getURI()));
        System.out.println("Signed by       : " + r.verificationMethod());
        System.out.println("Signature       : " + (r.signatureValid() ? "OK" : "INVALID"));
        if ( r.timestamps().isEmpty() )
            System.out.println("Timestamp       : none");
        for ( AttestationTimestamps.Check c : r.timestamps() ) {
            Rfc3161.TokenCheck t = c.token();
            String trust = t.trusted() == null ? "trust not checked"
                    : t.trusted() ? "trusted" : "UNTRUSTED: no path to a trust anchor";
            System.out.println("Timestamp       : " + (t.valid() ? "OK" : "INVALID") + "  " + (t.genTime() == null ? "?" : t.genTime())
                               + "  (" + trust + ")");
            System.out.println("  TSA           : " + (t.tsaName() == null ? "?" : t.tsaName())
                               + (c.authority() == null ? "" : "  via " + c.authority()));
        }
        System.out.println("Requested by    : " + r.requester().map(Requester::toString).orElse("(not recorded)"));
        System.out.println("Dataset state   : " + (r.datasetState() == null ? "?" : r.datasetState().getURI()) + "  (version "
                           + r.dataVersion() + ")");
        System.out.println("Solutions       : " + r.solutionCount() + " attested, " + r.rowsChecked() + " row(s) carry this attestation");
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
                Usage: verify --results <results.srj|.srx|.tsv> --attestation <attestation.ttl|.jsonld|.nt>
                              [--expect-key did:key:...]... [--trusted-keys <keys.json>]...
                              [--tsa-trust system|none|<anchors.pem>] [--require-timestamp]
                  Verifies the Data Integrity proof (ecdsa-rdfc-2019 or eddsa-rdfc-2022) of a result
                  attestation and that the rows carrying the attestation IRI match its RDFC-1.0 digest.
                  --expect-key and --trusted-keys (a JWK Set, such as the server's /$/provenance/keys)
                  restrict the keys the attestation may be signed with; both can be repeated. RFC 3161 timestamps on the attestation are
                  checked too; their TSA certificates are chained to the JVM trust store (system, the
                  default), to the certificates in a PEM file, or not at all (none). An untrusted
                  timestamp is reported but only fails verification with --require-timestamp, which
                  demands at least one valid timestamp that is not untrusted.
                  Exit: 0 valid, 1 invalid, 2 error.""");
    }
}
