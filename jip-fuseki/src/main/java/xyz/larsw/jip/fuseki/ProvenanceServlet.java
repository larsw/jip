package xyz.larsw.jip.fuseki;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
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
import xyz.larsw.jip.cert.CertificateBuilder;
import xyz.larsw.jip.cert.CertificateStore;
import xyz.larsw.jip.cert.ProvenanceKeys;
import xyz.larsw.jip.cert.SigningKey;
import xyz.larsw.jip.version.DataVersion;
import xyz.larsw.jip.version.DataVersionComponent;

/**
 * Read-only endpoints under {@code /$/provenance/}:
 * <ul>
 * <li>{@code GET certificate/{uuid}}: a stored certificate (Turtle, JSON-LD, N-Triples, N-Quads
 * or RDF/XML by content negotiation; {@code ?format=ttl|jsonld|nt|nq} overrides).</li>
 * <li>{@code GET key}: the signing key as did:key, publicKeyMultibase, JWK and PEM.</li>
 * <li>{@code GET version/{dataset}}: the persistent and TDB2-internal data versions.</li>
 * </ul>
 */
public class ProvenanceServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    private static final AcceptList OFFER = AcceptList.create(
            "text/turtle", "application/ld+json", "application/n-triples", "application/n-quads", "application/rdf+xml");

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String path = req.getPathInfo() == null ? "" : req.getPathInfo();
        try {
            if ( path.startsWith("/certificate/") )
                certificate(path.substring("/certificate/".length()), req, resp);
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

    private void certificate(String id, HttpServletRequest req, HttpServletResponse resp) throws IOException {
        if ( id.startsWith("urn:uuid:") )
            id = id.substring("urn:uuid:".length());
        UUID uuid = UUID.fromString(id);
        Node cert = CertificateBuilder.certificateNode(uuid);
        Optional<Graph> graph = CertificateStore.fromContext(ARQ.getContext()).get(cert);
        if ( graph.isEmpty() ) {
            resp.sendError(HttpServletResponse.SC_NOT_FOUND, "No certificate " + cert.getURI());
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
        SigningKey key = ProvenanceKeys.get();
        JsonObject obj = new JsonObject();
        obj.put("id", key.didKey());
        obj.put("verificationMethod", key.verificationMethod());
        obj.put("type", "Multikey");
        obj.put("publicKeyMultibase", key.publicKeyMultibase());
        obj.put("publicKeyJwk", org.apache.jena.atlas.json.JSON.parse(key.jwk()));
        obj.put("publicKeyPem", key.publicPem());
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
        byte[] bytes = (obj.toString() + "\n").getBytes(StandardCharsets.UTF_8);
        resp.setStatus(HttpServletResponse.SC_OK);
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");
        resp.setContentLength(bytes.length);
        try ( OutputStream out = resp.getOutputStream() ) {
            out.write(bytes);
        }
    }
}
