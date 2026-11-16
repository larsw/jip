package org.example.jena.provenance.fuseki;

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
import java.util.List;
import java.util.Optional;

import org.apache.jena.atlas.json.JSON;
import org.apache.jena.atlas.json.JsonObject;
import org.apache.jena.fuseki.main.FusekiServer;
import org.apache.jena.fuseki.main.sys.FusekiModules;
import org.apache.jena.graph.Graph;
import org.apache.jena.graph.GraphMemFactory;
import org.apache.jena.graph.Node;
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
import org.example.jena.provenance.cert.CertificateVerifier;
import org.example.jena.provenance.cert.ProvenanceKeys;
import org.example.jena.provenance.version.DataVersion;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** End-to-end over HTTP with the Docker configuration file (paths redirected to a temp dir). */
class FusekiIntegrationTest {

    @TempDir
    Path tmp;
    FusekiServer server;
    String base;
    final HttpClient http = HttpClient.newHttpClient();

    static final String CERTIFIED_QUERY = """
            PREFIX ex: <http://example.org/>
            SELECT ?name ?email ?cert WHERE {
              SERVICE <urn:x-provenance:certify> {
                SELECT ?name ?email WHERE { ?p ex:name ?name OPTIONAL { ?p ex:email ?email } } ORDER BY ?name
              }
            }
            """;

    @BeforeEach
    void start() throws Exception {
        System.setProperty(ProvenanceKeys.PROP_KEY_FILE, tmp.resolve("keys/signing-key.pem").toString());
        ProvenanceKeys.set(null);
        String config = Files.readString(Path.of("../docker/config.ttl"))
                .replace("/fuseki/databases", tmp.resolve("databases").toString());
        Model model = ModelFactory.createDefaultModel();
        RDFParser.fromString(config, Lang.TTL).base("http://base/").parse(model);
        server = FusekiServer.create()
                .port(0)
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
        ProvenanceKeys.set(null);
        TDBInternal.reset();
        DataVersion.resetForTesting();
    }

    HttpResponse<String> send(HttpRequest.Builder b) throws Exception {
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    HttpResponse<String> query(String q) throws Exception {
        return send(HttpRequest.newBuilder(URI.create(base + "/ds/sparql?query=" + URLEncoder.encode(q, StandardCharsets.UTF_8)))
                .header("Accept", "application/sparql-results+json"));
    }

    HttpResponse<String> update(String u) throws Exception {
        return send(HttpRequest.newBuilder(URI.create(base + "/ds/update"))
                .header("Content-Type", "application/sparql-update")
                .POST(HttpRequest.BodyPublishers.ofString(u)));
    }

    static long versionHeader(HttpResponse<?> r) {
        return Long.parseLong(r.headers().firstValue("X-Dataset-Version").orElseThrow(() -> new AssertionError("no X-Dataset-Version")));
    }

    @Test
    void endToEnd() throws Exception {
        // Load data with the Graph Store Protocol: a committed write -> version 1.
        HttpResponse<String> put = send(HttpRequest.newBuilder(URI.create(base + "/ds/data?default"))
                .header("Content-Type", "text/turtle")
                .POST(HttpRequest.BodyPublishers.ofString("""
                        PREFIX ex: <http://example.org/>
                        ex:alice ex:name "Alice" ; ex:email "alice@example.org" .
                        ex:bob   ex:name "Bob" .
                        """)));
        assertTrue(put.statusCode() / 100 == 2, "GSP POST: " + put.statusCode() + " " + put.body());
        assertEquals(1, versionHeader(put), "write response reports the version it committed");
        String datasetId = put.headers().firstValue("X-Dataset-Id").orElseThrow();
        assertTrue(datasetId.startsWith("urn:uuid:"));

        // Certified query.
        HttpResponse<String> res = query(CERTIFIED_QUERY);
        assertEquals(200, res.statusCode(), res.body());
        assertEquals(1, versionHeader(res), "read response reports its snapshot");
        assertEquals(datasetId, res.headers().firstValue("X-Dataset-Id").orElseThrow());

        RowSet rows = RowSet.adapt(ResultSetMgr.read(new ByteArrayInputStream(res.body().getBytes(StandardCharsets.UTF_8)),
                                                     ResultSetLang.RS_JSON));
        List<String> vars = rows.getResultVars().stream().map(Var::getVarName).toList();
        List<Binding> bindings = new ArrayList<>();
        rows.forEachRemaining(bindings::add);
        assertEquals(2, bindings.size());
        Node cert = bindings.get(0).get(Var.alloc("cert"));
        String uuid = cert.getURI().substring("urn:uuid:".length());

        // Fetch the certificate (Turtle) and the key; verify independently.
        HttpResponse<String> certRes = send(HttpRequest.newBuilder(URI.create(base + "/$/provenance/certificate/" + uuid))
                .header("Accept", "text/turtle"));
        assertEquals(200, certRes.statusCode(), certRes.body());
        Graph certGraph = GraphMemFactory.createDefaultGraph();
        RDFParser.fromString(certRes.body(), Lang.TURTLE).parse(certGraph);

        JsonObject key = JSON.parse(send(HttpRequest.newBuilder(URI.create(base + "/$/provenance/key"))).body());
        String didKey = key.get("id").getAsString().value();
        assertTrue(didKey.startsWith("did:key:z6Mk"));

        CertificateVerifier.Report report = CertificateVerifier.verify(certGraph, vars, bindings, Optional.of(didKey));
        assertTrue(report.valid(), () -> report.problems().toString());
        assertEquals(1, report.dataVersion());

        // JSON-LD form is offered too.
        HttpResponse<String> jsonld = send(HttpRequest.newBuilder(URI.create(base + "/$/provenance/certificate/" + uuid))
                .header("Accept", "application/ld+json"));
        assertEquals(200, jsonld.statusCode());
        assertTrue(jsonld.headers().firstValue("Content-Type").orElse("").startsWith("application/ld+json"));

        // The certificate store is queryable.
        HttpResponse<String> provQ = send(HttpRequest.newBuilder(URI.create(base + "/provenance/sparql?query="
                + URLEncoder.encode("ASK { GRAPH <" + cert.getURI() + "> { ?s ?p ?o } }", StandardCharsets.UTF_8)))
                .header("Accept", "application/sparql-results+json"));
        assertTrue(provQ.body().contains("true"), provQ.body());

        // Update -> version 2, reported on the update response, the version endpoint and new certificates.
        HttpResponse<String> upd = update("PREFIX ex: <http://example.org/> INSERT DATA { ex:carol ex:name \"Carol\" }");
        assertTrue(upd.statusCode() / 100 == 2, upd.body());
        assertEquals(2, versionHeader(upd));

        JsonObject version = JSON.parse(send(HttpRequest.newBuilder(URI.create(base + "/$/provenance/version/ds"))).body());
        assertEquals(2, version.get("version").getAsNumber().value().longValue());
        assertEquals(datasetId, version.get("datasetId").getAsString().value());

        HttpResponse<String> fn = query("PREFIX jip: <https://larsw.xyz/jip/> SELECT (jip:dataVersion() AS ?v) {}");
        assertTrue(fn.body().contains("\"2\""), fn.body());
        assertEquals(2, versionHeader(fn));

        // Unversioned dataset: the certify SERVICE is refused.
        HttpResponse<String> refused = send(HttpRequest.newBuilder(URI.create(base + "/provenance/sparql?query="
                + URLEncoder.encode("SELECT * { SERVICE <urn:x-provenance:certify> { ?s ?p ?o } }", StandardCharsets.UTF_8))));
        assertNotEquals(200, refused.statusCode());
        assertTrue(refused.headers().firstValue("X-Dataset-Version").isEmpty(), "no header for unversioned datasets");
    }
}
