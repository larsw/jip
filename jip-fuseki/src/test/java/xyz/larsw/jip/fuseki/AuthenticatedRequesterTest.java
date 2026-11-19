package xyz.larsw.jip.fuseki;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import org.apache.jena.atlas.web.AuthScheme;
import org.apache.jena.fuseki.auth.Auth;
import org.apache.jena.fuseki.main.FusekiServer;
import org.apache.jena.fuseki.main.sys.FusekiModules;
import org.apache.jena.graph.Graph;
import org.apache.jena.graph.GraphMemFactory;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFParser;
import org.apache.jena.riot.ResultSetMgr;
import org.apache.jena.riot.resultset.ResultSetLang;
import org.apache.jena.sparql.core.Var;
import org.apache.jena.sparql.engine.binding.Binding;
import org.apache.jena.sparql.exec.RowSet;
import org.apache.jena.tdb2.sys.TDBInternal;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import xyz.larsw.jip.attestation.AttestationVerifier;
import xyz.larsw.jip.attestation.ProvenanceKeys;
import xyz.larsw.jip.attestation.Requester;
import xyz.larsw.jip.version.DataVersion;

/** Over HTTP with Basic authentication: attestations name the authenticated user. */
class AuthenticatedRequesterTest {

    @TempDir
    Path tmp;
    FusekiServer server;
    String base;
    final HttpClient http = HttpClient.newHttpClient();

    static final String QUERY = """
            PREFIX ex: <http://example.org/>
            SELECT ?name ?attestation WHERE {
              SERVICE <urn:x-provenance:attest> { SELECT ?name WHERE { ?p ex:name ?name } ORDER BY ?name }
            }
            """;

    @BeforeEach
    void start() throws Exception {
        System.setProperty(ProvenanceKeys.PROP_SIGNER, "local");
        System.setProperty(ProvenanceKeys.PROP_KEY_FILE, tmp.resolve("keys/signing-key.pem").toString());
        ProvenanceKeys.set(null);
        Path passwd = Files.writeString(tmp.resolve("passwd"), "alice: alice-pw\nbob: bob-pw\n");
        String config = Files.readString(Path.of("../docker/config.ttl")).replace("/fuseki/databases", tmp.resolve("databases").toString());
        Model model = ModelFactory.createDefaultModel();
        RDFParser.fromString(config, Lang.TTL).base("http://base/").parse(model);
        server = FusekiServer.create()
                .port(0)
                .passwordFile(passwd.toString())
                .auth(AuthScheme.BASIC)
                .serverAuthPolicy(Auth.ANY_USER)
                .fusekiModules(FusekiModules.create(new ProvenanceFusekiModule()))
                .parseConfig(model)
                .build()
                .start();
        base = "http://localhost:" + server.getHttpPort();
    }

    @AfterEach
    void stop() {
        if ( server != null )
            server.stop();
        System.clearProperty(ProvenanceKeys.PROP_KEY_FILE);
        System.clearProperty(ProvenanceKeys.PROP_SIGNER);
        ProvenanceKeys.set(null);
        TDBInternal.reset();
        DataVersion.resetForTesting();
    }

    HttpResponse<String> send(HttpRequest.Builder b, String user, String password) throws Exception {
        if ( user != null )
            b.header("Authorization", "Basic " + Base64.getEncoder().encodeToString((user + ":" + password).getBytes(StandardCharsets.UTF_8)));
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    HttpResponse<String> query(String user, String password) throws Exception {
        return send(HttpRequest.newBuilder(URI.create(base + "/ds/sparql?query=" + URLEncoder.encode(QUERY, StandardCharsets.UTF_8)))
                .header("Accept", "application/sparql-results+json"), user, password);
    }

    /** Run the attested query as {@code user}, fetch its attestation and verify it. */
    AttestationVerifier.Report attestedAs(String user, String password) throws Exception {
        HttpResponse<String> res = query(user, password);
        assertEquals(200, res.statusCode(), res.body());
        RowSet rows = RowSet.adapt(ResultSetMgr.read(new ByteArrayInputStream(res.body().getBytes(StandardCharsets.UTF_8)), ResultSetLang.RS_JSON));
        List<String> vars = rows.getResultVars().stream().map(Var::getVarName).toList();
        List<Binding> bindings = new ArrayList<>();
        rows.forEachRemaining(bindings::add);
        String uuid = bindings.get(0).get(Var.alloc("attestation")).getURI().substring("urn:uuid:".length());
        HttpResponse<String> att = send(HttpRequest.newBuilder(URI.create(base + "/$/provenance/attestation/" + uuid))
                .header("Accept", "text/turtle"), user, password);
        assertEquals(200, att.statusCode(), att.body());
        Graph g = GraphMemFactory.createDefaultGraph();
        RDFParser.fromString(att.body(), Lang.TURTLE).parse(g);
        AttestationVerifier.Report report = AttestationVerifier.verify(g, vars, bindings, Optional.of(ProvenanceKeys.get().didKey()));
        assertTrue(report.valid(), () -> report.problems().toString());
        return report;
    }

    @Test
    void attestationsNameTheAuthenticatedUser() throws Exception {
        HttpResponse<String> load = send(HttpRequest.newBuilder(URI.create(base + "/ds/data?default"))
                .header("Content-Type", "text/turtle")
                .POST(HttpRequest.BodyPublishers.ofString("<http://example.org/a> <http://example.org/name> \"A\" .")), "alice", "alice-pw");
        assertTrue(load.statusCode() / 100 == 2, load.body());

        assertEquals(401, query(null, null).statusCode(), "anonymous requests are refused");
        assertEquals(401, query("alice", "wrong").statusCode());

        assertEquals(Optional.of(new Requester("alice", "BASIC")), attestedAs("alice", "alice-pw").requester());
        assertEquals(Optional.of(new Requester("bob", "BASIC")), attestedAs("bob", "bob-pw").requester());
    }
}
