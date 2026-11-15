package org.example.jena.provenance.fuseki;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Optional;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import org.example.jena.provenance.JIP;
import org.example.jena.provenance.version.RequestVersionTracker;

/**
 * Sets {@code X-Dataset-Version} and {@code X-Dataset-Id} on responses of requests that read or
 * committed a versioned dataset.
 * <p>
 * The data version component records the version on the request thread when a transaction
 * begins (reads) or commits (writes). The headers are set at the last moment they can be: just
 * before the first byte of the body is written or flushed, or after the request if the
 * response is still uncommitted. Fuseki begins the query transaction before it writes results,
 * so the header reports exactly the snapshot the results came from.
 */
public class DataVersionHeaderFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if ( !(response instanceof HttpServletResponse httpResponse) ) {
            chain.doFilter(request, response);
            return;
        }
        RequestVersionTracker.start();
        try {
            VersionHeaderResponse wrapped = new VersionHeaderResponse(httpResponse);
            chain.doFilter(request, wrapped);
            wrapped.applyHeaders();
        } finally {
            RequestVersionTracker.stop();
        }
    }

    static final class VersionHeaderResponse extends HttpServletResponseWrapper {
        private boolean applied = false;
        private ServletOutputStream stream;

        VersionHeaderResponse(HttpServletResponse response) {
            super(response);
        }

        void applyHeaders() {
            if ( applied || isCommitted() )
                return;
            Optional<RequestVersionTracker.Observation> obs = RequestVersionTracker.current();
            if ( obs.isEmpty() )
                return;     // maybe later (e.g. stream obtained before the transaction began)
            applied = true;
            setHeader(JIP.HEADER_DATASET_VERSION, Long.toString(obs.get().version()));
            setHeader(JIP.HEADER_DATASET_ID, "urn:uuid:" + obs.get().databaseId());
        }

        @Override
        public ServletOutputStream getOutputStream() throws IOException {
            if ( stream == null )
                stream = new HeaderOnFirstWrite(super.getOutputStream(), this);
            return stream;
        }

        @Override
        public PrintWriter getWriter() throws IOException {
            applyHeaders();
            return super.getWriter();
        }

        @Override
        public void flushBuffer() throws IOException {
            applyHeaders();
            super.flushBuffer();
        }
    }

    /** Applies the headers before the first byte is written or flushed. */
    static final class HeaderOnFirstWrite extends ServletOutputStream {
        private final ServletOutputStream out;
        private final VersionHeaderResponse response;

        HeaderOnFirstWrite(ServletOutputStream out, VersionHeaderResponse response) {
            this.out = out;
            this.response = response;
        }

        @Override
        public void write(int b) throws IOException {
            response.applyHeaders();
            out.write(b);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            response.applyHeaders();
            out.write(b, off, len);
        }

        @Override
        public void flush() throws IOException {
            response.applyHeaders();
            out.flush();
        }

        @Override
        public void close() throws IOException {
            response.applyHeaders();
            out.close();
        }

        @Override
        public boolean isReady() {
            return out.isReady();
        }

        @Override
        public void setWriteListener(WriteListener writeListener) {
            out.setWriteListener(writeListener);
        }
    }
}
