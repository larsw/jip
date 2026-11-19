package xyz.larsw.jip.service;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import org.apache.jena.query.QueryBuildException;
import org.apache.jena.sparql.core.Var;
import xyz.larsw.jip.JIP;

/**
 * Parameters of an attest SERVICE IRI: {@code <urn:x-provenance:attest?var=attestation&empty=row>}.
 *
 * @param attestationVar   variable bound to the attestation IRI (default {@code ?attestation})
 * @param emptyRow  on an empty result, emit one attestation-only row (default) or nothing
 */
public record AttestRequest(Var attestationVar, boolean emptyRow) {

    public static final String DEFAULT_VAR = "attestation";

    public static boolean matches(String serviceIRI) {
        return serviceIRI.equals(JIP.SERVICE_ATTEST) || serviceIRI.startsWith(JIP.SERVICE_ATTEST + "?");
    }

    public static AttestRequest parse(String serviceIRI) {
        String var = DEFAULT_VAR;
        boolean emptyRow = true;
        int q = serviceIRI.indexOf('?');
        if ( q >= 0 ) {
            for ( String pair : serviceIRI.substring(q + 1).split("&") ) {
                if ( pair.isEmpty() )
                    continue;
                int eq = pair.indexOf('=');
                String key = decode(eq < 0 ? pair : pair.substring(0, eq));
                String value = eq < 0 ? "" : decode(pair.substring(eq + 1));
                switch (key) {
                    case "var" -> var = value.startsWith("?") ? value.substring(1) : value;
                    case "empty" -> {
                        switch (value) {
                            case "row" -> emptyRow = true;
                            case "none" -> emptyRow = false;
                            default -> throw new QueryBuildException("Attest SERVICE: empty must be 'row' or 'none': " + value);
                        }
                    }
                    default -> throw new QueryBuildException("Attest SERVICE: unknown parameter '" + key + "'");
                }
            }
        }
        if ( !Var.isNamedVarName(var) || var.isEmpty() || !var.matches("[A-Za-z_][A-Za-z0-9_]*") )
            throw new QueryBuildException("Attest SERVICE: invalid variable name '" + var + "'");
        return new AttestRequest(Var.alloc(var), emptyRow);
    }

    private static String decode(String s) {
        return URLDecoder.decode(s, StandardCharsets.UTF_8);
    }
}
