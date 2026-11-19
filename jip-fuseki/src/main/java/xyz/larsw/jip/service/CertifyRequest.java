package xyz.larsw.jip.service;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import org.apache.jena.query.QueryBuildException;
import org.apache.jena.sparql.core.Var;
import xyz.larsw.jip.JIP;

/**
 * Parameters of a certify SERVICE IRI: {@code <urn:x-provenance:certify?var=cert&empty=row>}.
 *
 * @param certVar   variable bound to the certificate IRI (default {@code ?cert})
 * @param emptyRow  on an empty result, emit one certificate-only row (default) or nothing
 */
public record CertifyRequest(Var certVar, boolean emptyRow) {

    public static final String DEFAULT_VAR = "cert";

    public static boolean matches(String serviceIRI) {
        return serviceIRI.equals(JIP.SERVICE_CERTIFY) || serviceIRI.startsWith(JIP.SERVICE_CERTIFY + "?");
    }

    public static CertifyRequest parse(String serviceIRI) {
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
                            default -> throw new QueryBuildException("Certify SERVICE: empty must be 'row' or 'none': " + value);
                        }
                    }
                    default -> throw new QueryBuildException("Certify SERVICE: unknown parameter '" + key + "'");
                }
            }
        }
        if ( !Var.isNamedVarName(var) || var.isEmpty() || !var.matches("[A-Za-z_][A-Za-z0-9_]*") )
            throw new QueryBuildException("Certify SERVICE: invalid variable name '" + var + "'");
        return new CertifyRequest(Var.alloc(var), emptyRow);
    }

    private static String decode(String s) {
        return URLDecoder.decode(s, StandardCharsets.UTF_8);
    }
}
