package xyz.larsw.jip.cert;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;

/**
 * The parts of the RFC 3161 Time-Stamp Protocol that jip needs, without any network access:
 * building a request, accepting a reply, and verifying a token offline.
 * <p>
 * Only SHA-256 message imprints are requested and accepted. Revocation of TSA certificates is
 * not checked.
 */
public final class Rfc3161 {
    private Rfc3161() {}

    /** Media type of a request (RFC 3161 §3.4). */
    public static final String MEDIA_TYPE_QUERY = "application/timestamp-query";
    /** Media type of a reply (RFC 3161 §3.4). */
    public static final String MEDIA_TYPE_REPLY = "application/timestamp-reply";

    /**
     * Result of checking one token.
     *
     * @param genTime         the TSA's time, or null if the token cannot be read
     * @param tsaName         the subject of the TSA's signing certificate, if known
     * @param policy          the TSA policy OID
     * @param imprintValid    the token covers the expected SHA-256 message imprint
     * @param signatureValid  the TSA's signature over the token verifies with the certificate in
     *                        the token, and that certificate is a time-stamping certificate
     *                        valid at {@code genTime}
     * @param trusted         the TSA certificate chains to a trust anchor at {@code genTime};
     *                        null if the chain was not checked
     * @param problems        why the token is not valid; empty if it is
     */
    public record TokenCheck(Instant genTime, String tsaName, String policy,
                             boolean imprintValid, boolean signatureValid, Boolean trusted,
                             List<String> problems) {
        /** The token is intact and covers the expected data. Says nothing about trust. */
        public boolean valid() {
            return imprintValid && signatureValid && problems.isEmpty();
        }

        /** Valid, and not shown to be untrusted (trusted, or trust not checked). */
        public boolean acceptable() {
            return valid() && !Boolean.FALSE.equals(trusted);
        }

        static TokenCheck unreadable(String problem) {
            return new TokenCheck(null, null, null, false, false, null, List.of(problem));
        }
    }

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    /** A request for a SHA-256 imprint, asking for the TSA certificate in the reply. */
    public static TimeStampRequest request(byte[] sha256Imprint, BigInteger nonce) {
        TimeStampRequestGenerator gen = new TimeStampRequestGenerator();
        gen.setCertReq(true);
        return gen.generate(TSPAlgorithms.SHA256, sha256Imprint, nonce);
    }

    /**
     * Accept a TSA reply to {@code request}: it must grant a token for the same imprint and
     * nonce, with the TSA certificate included.
     *
     * @return the DER encoding of the token (a CMS SignedData)
     * @throws TSPException if the reply is a refusal or does not match the request
     */
    public static byte[] tokenFromReply(TimeStampRequest request, byte[] reply) throws TSPException, IOException {
        TimeStampResponse response = new TimeStampResponse(reply);
        int status = response.getStatus();
        if ( status != PKIStatus.GRANTED && status != PKIStatus.GRANTED_WITH_MODS )
            throw new TSPException("TSA refused the request (status " + status
                                   + (response.getStatusString() == null ? "" : ": " + response.getStatusString()) + ")");
        response.validate(request);
        TimeStampToken token = response.getTimeStampToken();
        if ( token == null )
            throw new TSPException("TSA reply has no token");
        return token.getEncoded();
    }

    /** The time in a token, without verifying it. */
    public static Instant genTime(byte[] token) throws TSPException, IOException {
        try {
            return new TimeStampToken(new CMSSignedData(token)).getTimeStampInfo().getGenTime().toInstant();
        } catch (org.bouncycastle.cms.CMSException ex) {
            throw new TSPException("Not a time-stamp token: " + ex.getMessage(), ex);
        }
    }

    /**
     * Verify a token offline.
     *
     * @param token            DER-encoded token
     * @param expectedImprint  the SHA-256 digest the token must cover
     * @param trustAnchors     anchors the TSA certificate must chain to (at the token's time);
     *                         empty to skip the chain check
     */
    public static TokenCheck verify(byte[] token, byte[] expectedImprint, Optional<Set<TrustAnchor>> trustAnchors) {
        TimeStampToken tst;
        try {
            tst = new TimeStampToken(new CMSSignedData(token));
        } catch (Exception ex) {
            return TokenCheck.unreadable("Not a readable time-stamp token: " + ex.getMessage());
        }
        List<String> problems = new ArrayList<>();
        TimeStampTokenInfo info = tst.getTimeStampInfo();
        Instant genTime = info.getGenTime().toInstant();
        String policy = info.getPolicy() == null ? null : info.getPolicy().getId();

        boolean imprintOk = TSPAlgorithms.SHA256.equals(info.getMessageImprintAlgOID())
                            && Arrays.equals(info.getMessageImprintDigest(), expectedImprint);
        if ( !imprintOk )
            problems.add("Timestamp does not cover this certificate's signature (message imprint mismatch)");

        List<X509Certificate> certs = certificates(tst);
        Optional<X509CertificateHolder> signer = signerCertificate(tst);
        String tsaName = signer.map(h -> h.getSubject().toString())
                .orElse(info.getTsa() == null ? null : info.getTsa().getName().toString());
        boolean signatureOk = false;
        if ( signer.isEmpty() ) {
            problems.add("Token does not include the TSA certificate");
        } else {
            try {
                // Checks the CMS signature, the ESS certificate binding, that the certificate is
                // a time-stamping certificate (critical EKU id-kp-timeStamping only) and that it
                // was valid at genTime.
                tst.validate(new JcaSimpleSignerInfoVerifierBuilder().build(signer.get()));
                signatureOk = true;
            } catch (Exception ex) {
                problems.add("TSA signature does not verify: " + ex.getMessage());
            }
        }

        Boolean trusted = null;
        if ( trustAnchors.isPresent() && signatureOk )
            trusted = chainsToAnchor(toX509(signer.get()), certs, trustAnchors.get(), Date.from(genTime));
        return new TokenCheck(genTime, tsaName, policy, imprintOk, signatureOk, trusted, List.copyOf(problems));
    }

    /** The trust anchors of the JVM's default trust store (normally {@code cacerts}). */
    public static Set<TrustAnchor> systemTrustAnchors() {
        return SystemAnchors.ANCHORS;
    }

    /** Trust anchors from a file of PEM (or DER) certificates. */
    public static Set<TrustAnchor> trustAnchors(Path file) {
        try ( InputStream in = Files.newInputStream(file) ) {
            Collection<? extends Certificate> certs = CertificateFactory.getInstance("X.509").generateCertificates(in);
            Set<TrustAnchor> anchors = new HashSet<>();
            for ( Certificate c : certs )
                anchors.add(new TrustAnchor((X509Certificate)c, null));
            if ( anchors.isEmpty() )
                throw new IllegalArgumentException("No certificates in " + file);
            return Set.copyOf(anchors);
        } catch (IOException ex) {
            throw new UncheckedIOException(file.toString(), ex);
        } catch (CertificateException ex) {
            throw new IllegalArgumentException("Cannot read certificates from " + file + ": " + ex.getMessage(), ex);
        }
    }

    private static final class SystemAnchors {
        static final Set<TrustAnchor> ANCHORS = load();

        private static Set<TrustAnchor> load() {
            try {
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init((KeyStore)null);
                Set<TrustAnchor> anchors = new HashSet<>();
                for ( TrustManager tm : tmf.getTrustManagers() ) {
                    if ( tm instanceof X509TrustManager x )
                        for ( X509Certificate c : x.getAcceptedIssuers() )
                            anchors.add(new TrustAnchor(c, null));
                }
                return Set.copyOf(anchors);
            } catch (GeneralSecurityException ex) {
                throw new IllegalStateException("Cannot load the default trust store", ex);
            }
        }
    }

    private static boolean chainsToAnchor(X509Certificate target, List<X509Certificate> others, Set<TrustAnchor> anchors, Date at) {
        for ( TrustAnchor a : anchors ) {
            if ( target.equals(a.getTrustedCert()) )
                return true;
        }
        try {
            X509CertSelector selector = new X509CertSelector();
            selector.setCertificate(target);
            PKIXBuilderParameters params = new PKIXBuilderParameters(anchors, selector);
            params.setRevocationEnabled(false);
            params.setDate(at);
            params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(others)));
            CertPathBuilder.getInstance("PKIX").build(params);
            return true;
        } catch (GeneralSecurityException ex) {
            return false;
        }
    }

    private static Optional<X509CertificateHolder> signerCertificate(TimeStampToken tst) {
        @SuppressWarnings("unchecked")
        Collection<X509CertificateHolder> matches = tst.getCertificates().getMatches(tst.getSID());
        return matches.stream().findFirst();
    }

    private static List<X509Certificate> certificates(TimeStampToken tst) {
        List<X509Certificate> out = new ArrayList<>();
        for ( X509CertificateHolder h : tst.getCertificates().getMatches(null) )
            out.add(toX509(h));
        return out;
    }

    private static X509Certificate toX509(X509CertificateHolder h) {
        try {
            return new JcaX509CertificateConverter().getCertificate(h);
        } catch (CertificateException ex) {
            throw new IllegalArgumentException("Bad certificate in token: " + ex.getMessage(), ex);
        }
    }
}
