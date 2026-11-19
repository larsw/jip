package xyz.larsw.jip.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Exit status contract: 0 valid, 1 invalid, 2 usage or input error. */
class VerifyTest {

    @TempDir
    Path tmp;
    String results;
    String cert;

    @BeforeEach
    void files() throws IOException {
        results = Files.writeString(tmp.resolve("results.srj"), """
                { "head": { "vars": [ "name", "cert" ] }, "results": { "bindings": [] } }
                """).toString();
        // Parses, but holds no jip:ResultCertificate.
        cert = Files.writeString(tmp.resolve("certificate.ttl"), "<urn:x:s> <urn:x:p> <urn:x:o> .\n").toString();
    }

    @Test
    void help() {
        assertEquals(0, Verify.run("--help"));
    }

    @Test
    void notACertificateIsInvalid() {
        assertEquals(1, Verify.run("--results", results, "--cert", cert));
    }

    @Test
    void missingOptionValueIsUsageError() {
        assertEquals(2, Verify.run("--results", results, "--cert"));
        assertEquals(2, Verify.run("--cert", cert, "-r"));
        assertEquals(2, Verify.run("--results", results, "--cert", cert, "--expect-key"));
        assertEquals(2, Verify.run("--results", "", "--cert", cert));
    }

    @Test
    void optionInPlaceOfValueIsUsageError() {
        assertEquals(2, Verify.run("--results", "--cert", cert));
        assertEquals(2, Verify.run("--results", results, "--cert", cert, "-k", "--help"));
    }

    @Test
    void missingRequiredOptionIsUsageError() {
        assertEquals(2, Verify.run());
        assertEquals(2, Verify.run("--results", results));
        assertEquals(2, Verify.run("--cert", cert));
    }

    @Test
    void unknownArgumentIsUsageError() {
        assertEquals(2, Verify.run("--results", results, "--cert", cert, "--frobnicate"));
    }

    @Test
    void badFileNameIsUsageError() {
        assertEquals(2, Verify.run("--results", "bad\0name", "--cert", cert));
    }

    @Test
    void timestampOptions() {
        assertEquals(1, Verify.run("--results", results, "--cert", cert, "--tsa-trust", "none", "--require-timestamp"));
        assertEquals(2, Verify.run("--results", results, "--cert", cert, "--tsa-trust"));
        assertEquals(2, Verify.run("--results", results, "--cert", cert, "--tsa-trust", tmp.resolve("missing.pem").toString()));
    }

    @Test
    void unreadableInputIsError() {
        assertEquals(2, Verify.run("--results", tmp.resolve("missing.srj").toString(), "--cert", cert));
        assertEquals(2, Verify.run("--results", results, "--cert", tmp.resolve("missing.ttl").toString()));
    }
}
