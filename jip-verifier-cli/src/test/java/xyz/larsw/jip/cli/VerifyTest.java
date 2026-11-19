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
    String attestationFile;

    @BeforeEach
    void files() throws IOException {
        results = Files.writeString(tmp.resolve("results.srj"), """
                { "head": { "vars": [ "name", "attestation" ] }, "results": { "bindings": [] } }
                """).toString();
        // Parses, but holds no jip:ResultAttestation.
        attestationFile = Files.writeString(tmp.resolve("attestation.ttl"), "<urn:x:s> <urn:x:p> <urn:x:o> .\n").toString();
    }

    @Test
    void help() {
        assertEquals(0, Verify.run("--help"));
    }

    @Test
    void notAnAttestationIsInvalid() {
        assertEquals(1, Verify.run("--results", results, "--attestation", attestationFile));
    }

    @Test
    void missingOptionValueIsUsageError() {
        assertEquals(2, Verify.run("--results", results, "--attestation"));
        assertEquals(2, Verify.run("--attestation", attestationFile, "-r"));
        assertEquals(2, Verify.run("--results", results, "--attestation", attestationFile, "--expect-key"));
        assertEquals(2, Verify.run("--results", "", "--attestation", attestationFile));
    }

    @Test
    void optionInPlaceOfValueIsUsageError() {
        assertEquals(2, Verify.run("--results", "--attestation", attestationFile));
        assertEquals(2, Verify.run("--results", results, "--attestation", attestationFile, "-k", "--help"));
    }

    @Test
    void missingRequiredOptionIsUsageError() {
        assertEquals(2, Verify.run());
        assertEquals(2, Verify.run("--results", results));
        assertEquals(2, Verify.run("--attestation", attestationFile));
    }

    @Test
    void unknownArgumentIsUsageError() {
        assertEquals(2, Verify.run("--results", results, "--attestation", attestationFile, "--frobnicate"));
    }

    @Test
    void badFileNameIsUsageError() {
        assertEquals(2, Verify.run("--results", "bad\0name", "--attestation", attestationFile));
    }

    @Test
    void trustedKeysOption() throws IOException {
        assertEquals(2, Verify.run("--results", results, "--attestation", attestationFile, "--trusted-keys"));
        assertEquals(2, Verify.run("--results", results, "--attestation", attestationFile, "--trusted-keys", tmp.resolve("missing.json").toString()));
        String notAJwkSet = Files.writeString(tmp.resolve("bad.json"), "{\"keys\": 1}").toString();
        assertEquals(2, Verify.run("--results", results, "--attestation", attestationFile, "--trusted-keys", notAJwkSet));
    }

    @Test
    void timestampOptions() {
        assertEquals(1, Verify.run("--results", results, "--attestation", attestationFile, "--tsa-trust", "none", "--require-timestamp"));
        assertEquals(2, Verify.run("--results", results, "--attestation", attestationFile, "--tsa-trust"));
        assertEquals(2, Verify.run("--results", results, "--attestation", attestationFile, "--tsa-trust", tmp.resolve("missing.pem").toString()));
    }

    @Test
    void unreadableInputIsError() {
        assertEquals(2, Verify.run("--results", tmp.resolve("missing.srj").toString(), "--attestation", attestationFile));
        assertEquals(2, Verify.run("--results", results, "--attestation", tmp.resolve("missing.ttl").toString()));
    }
}
