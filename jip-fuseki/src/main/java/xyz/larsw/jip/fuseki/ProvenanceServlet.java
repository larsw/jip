package xyz.larsw.jip.fuseki;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.jena.atlas.json.JsonObject;
import org.apache.jena.atlas.web.AcceptList;
import org.apache.jena.atlas.web.MediaType;
import org.apache.jena.fuseki.server.DataAccessPoint;
import org.apache.jena.fuseki.server.DataAccessPointRegistry;
import org.apache.jena.graph.Graph;
import org.apache.jena.graph.Node;
import org.apache.jena.query.ARQ;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFDataMgr;
import org.apache.jena.riot.RDFFormat;
import org.apache.jena.riot.RDFLanguages;
import org.apache.jena.sparql.core.DatasetGraph;
import org.apache.jena.system.Txn;
import xyz.larsw.jip.attestation.AttestationBuilder;
import xyz.larsw.jip.attestation.AttestationStore;
import xyz.larsw.jip.attestation.ProvenanceKeys;
import xyz.larsw.jip.attestation.ProvenanceSigner;
import xyz.larsw.jip.attestation.TimestampAuthorities;
import xyz.larsw.jip.version.DataVersion;
import xyz.larsw.jip.version.DataVersionComponent;

/**
 * Read-only endpoints under {@code /$/provenance/}:
 * <ul>
 * <li>{@code GET attestation/{uuid}}: a stored attestation (Turtle, JSON-LD, N-Triples, N-Quads
 * or RDF/XML by content negotiation; {@code ?format=ttl|jsonld|nt|nq} overrides). While its RFC 3161
 * timestamp is still being fetched: {@code 202 Accepted} with {@code Retry-After} and a JSON status.</li>
 * <li>{@code GET key}: the signing key as did:key, publicKeyMultibase, JWK and PEM, with its key
 * type, cryptosuite and signer kind.</li>
 * <li>{@code GET version/{dataset}}: the persistent and TDB2-internal data versions.</li>
 * </ul>
 */
public class ProvenanceServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    /** Retry-After when the next timestamp attempt isn't known in this process. */
    static final long DEFAULT_RETRY_AFTER_SECONDS = 5;

    private static final AcceptList OFFER = AcceptList.create(
            "text/turtle", "application/ld+json", "application/n-triples", "application/n-quads", "application/rdf+xml");

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String path = req.getPathInfo() == null ? "" : req.getPathInfo();
        try {
            if ( path.startsWith("/attestation/") )
                attestation(path.substring("/attestation/".length()), req, resp);
            else if ( path.equals("/key") )
                key(resp);
            else if ( path.startsWith("/version/") )
                version(path.substring("/version/".length()), resp);
            else
                resp.sendError(HttpServletResponse.SC_NOT_FOUND, "Unknown provenance resource: " + path);
        } catch (IllegalArgumentException ex) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, ex.getMessage());
        }
    }

    private void attestation(String id, HttpServletRequest req, HttpServletResponse resp) throws IOException {
        if ( id.startsWith("urn:uuid:") )
            id = id.substring("urn:uuid:".length());
        UUID uuid = UUID.fromString(id);
        Node attestationIri = AttestationBuilder.attestationNode(uuid);
        AttestationStore store = AttestationStore.fromContext(ARQ.getContext());
        Optional<Instant> pendingSince = store.pendingSince(attestationIri);
        if ( pendingSince.isPresent() ) {
            timestampPending(attestationIri, pendingSince.get(), resp);
            return;
        }
        Optional<Graph> graph = store.get(attestationIri);
        if ( graph.isEmpty() ) {
            resp.sendError(HttpServletResponse.SC_NOT_FOUND, "No attestation " + attestationIri.getURI());
            return;
        }
        Lang lang = chooseLang(req);
        resp.setStatus(HttpServletResponse.SC_OK);
        resp.setContentType(lang.getContentType().getContentTypeStr());
        resp.setCharacterEncoding("UTF-8");
        resp.setHeader("Vary", "Accept");
        try ( OutputStream out = resp.getOutputStream() ) {
            if ( lang.equals(Lang.NQUADS) )
                RDFDataMgr.write(out, graph.get(), Lang.NTRIPLES);
            else if ( lang.equals(Lang.TURTLE) )
                RDFDataMgr.write(out, graph.get(), RDFFormat.TURTLE_PRETTY);
            else
                RDFDataMgr.write(out, graph.get(), lang);
        }
    }

    /**
     * The attestation exists and is signed, but its RFC 3161 timestamp has not landed yet:
     * {@code 202 Accepted} with {@code Retry-After} (seconds until the next attempt, at least 1).
     */
    private static void timestampPending(Node attestationIri, Instant since, HttpServletResponse resp) throws IOException {
        long retryAfter = DEFAULT_RETRY_AFTER_SECONDS;
        try {
            Optional<Duration> next = TimestampAuthorities.fromContext(ARQ.getContext()).flatMap(t -> t.untilNextAttempt(attestationIri));
            if ( next.isPresent() )
                retryAfter = Math.max(1, (next.get().toMillis() + 999) / 1000);
        } catch (IllegalArgumentException ignored) {}
        JsonObject obj = new JsonObject();
        obj.put("attestation", attestationIri.getURI());
        obj.put("status", "timestamp-pending");
        obj.put("pendingSince", since.toString());
        obj.put("retryAfter", retryAfter);
        resp.setHeader("Retry-After", Long.toString(retryAfter));
        resp.setHeader("Cache-Control", "no-store");
        json(resp, HttpServletResponse.SC_ACCEPTED, obj);
    }

    private static Lang chooseLang(HttpServletRequest req) {
        String format = req.getParameter("format");
        if ( format != null ) {
            return switch (format) {
                case "ttl", "turtle" -> Lang.TURTLE;
                case "jsonld", "json-ld" -> Lang.JSONLD;
                case "nt" -> Lang.NTRIPLES;
                case "nq" -> Lang.NQUADS;
                case "rdf", "xml" -> Lang.RDFXML;
                default -> throw new IllegalArgumentException("Unknown format: " + format);
            };
        }
        String accept = req.getHeader("Accept");
        if ( accept == null || accept.isBlank() )
            return Lang.TURTLE;
        MediaType chosen = AcceptList.match(AcceptList.create(accept), OFFER);
        Lang lang = chosen == null ? null : RDFLanguages.contentTypeToLang(chosen.getContentTypeStr());
        return lang == null ? Lang.TURTLE : lang;
    }

    private void key(HttpServletResponse resp) throws IOException {
        ProvenanceSigner key = ProvenanceKeys.get();
        JsonObject obj = new JsonObject();
        obj.put("id", key.didKey());
        obj.put("verificationMethod", key.verificationMethod());
        obj.put("type", "Multikey");
        obj.put("publicKeyMultibase", key.publicKeyMultibase());
        obj.put("publicKeyJwk", org.apache.jena.atlas.json.JSON.parse(key.jwk()));
        obj.put("publicKeyPem", key.publicPem());
        obj.put("keyType", key.keyType().curveName());
        obj.put("cryptosuite", key.keyType().cryptosuite());
        obj.put("signer", key.kind());
        json(resp, obj);
    }

    private void version(String datasetName, HttpServletResponse resp) throws IOException {
        DataAccessPointRegistry registry = DataAccessPointRegistry.get(getServletContext());
        String name = datasetName.startsWith("/") ? datasetName : "/" + datasetName;
        DataAccessPoint dap = registry == null ? null : registry.get(name);
        if ( dap == null ) {
            resp.sendError(HttpServletResponse.SC_NOT_FOUND, "No dataset " + name);
            return;
        }
        DatasetGraph dsg = dap.getDataService().getDataset();
        Optional<DataVersionComponent> component = DataVersion.find(dsg);
        if ( component.isEmpty() ) {
            resp.sendError(HttpServletResponse.SC_NOT_FOUND, "Dataset " + name + " has no persistent data version");
            return;
        }
        DataVersionComponent c = component.get();
        // One read transaction: both numbers describe the same snapshot.
        long[] v = Txn.calculateRead(dsg, () -> new long[] { c.currentVersion(), DataVersion.tdbInternalVersion(dsg) });
        JsonObject obj = new JsonObject();
        obj.put("dataset", name);
        obj.put("datasetId", "urn:uuid:" + c.databaseId());
        c.datasetIRI().ifPresent(iri -> obj.put("datasetIRI", iri));
        obj.put("version", v[0]);
        obj.put("tdbInternal", v[1]);
        obj.put("persistent", c.isPersistent());
        json(resp, obj);
    }

    private static void json(HttpServletResponse resp, JsonObject obj) throws IOException {
        json(resp, HttpServletResponse.SC_OK, obj);
    }

    private static void json(HttpServletResponse resp, int status, JsonObject obj) throws IOException {
        byte[] bytes = (obj.toString() + "\n").getBytes(StandardCharsets.UTF_8);
        resp.setStatus(status);
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");
        resp.setContentLength(bytes.length);
        try ( OutputStream out = resp.getOutputStream() ) {
            out.write(bytes);
        }
    }
}
