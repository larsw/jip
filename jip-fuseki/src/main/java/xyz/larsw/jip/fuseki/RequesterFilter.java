package xyz.larsw.jip.fuseki;

import java.io.IOException;
import java.util.Locale;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import xyz.larsw.jip.attestation.Requester;
import xyz.larsw.jip.service.RequestUser;

/**
 * Records the authenticated user of each request ({@code getRemoteUser()}, and the scheme)
 * for the attest SERVICE, which runs on the same thread. It must come after the authentication
 * filter (Shiro, Fuseki's bearer filter); Jetty-level authentication (Fuseki's password file) is
 * done before any filter. {@link ProvenanceFusekiModule} adds it in the {@code configured} step,
 * after the {@code prepare} step where the authentication modules add theirs.
 */
public class RequesterFilter implements Filter {

    /**
     * The authentication scheme: the container's {@code getAuthType()}, or else the scheme of the
     * {@code Authorization} header (Shiro authenticates without setting the auth type).
     */
    static String scheme(HttpServletRequest request) {
        String type = request.getAuthType();
        if ( type != null && !type.isBlank() )
            return type.toUpperCase(Locale.ROOT);
        String header = request.getHeader("Authorization");
        if ( header == null || header.isBlank() )
            return null;
        String scheme = header.strip().split("\\s+", 2)[0];
        return scheme.matches("[A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]*") ? scheme.toUpperCase(Locale.ROOT) : null;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        String user = request instanceof HttpServletRequest http ? http.getRemoteUser() : null;
        if ( user == null || user.isBlank() ) {
            chain.doFilter(request, response);
            return;
        }
        RequestUser.set(new Requester(user, scheme((HttpServletRequest)request)));
        try {
            chain.doFilter(request, response);
        } finally {
            RequestUser.clear();
        }
    }
}
