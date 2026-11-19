package xyz.larsw.jip.attestation;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import com.sun.net.httpserver.HttpServer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;

/**
 * A time-stamping authority for tests: a self-signed CA, a TSA certificate issued by it, and
 * optionally an HTTP endpoint speaking RFC 3161.
 */
public final class TestTsa implements AutoCloseable {
    public static final ASN1ObjectIdentifier POLICY = new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.1");

    private final KeyPair caKeys;
    private final X509Certificate caCert;
    private final KeyPair tsaKeys;
    private final X509Certificate tsaCert;
    private final AtomicLong serial = new AtomicLong(1);
    private final AtomicInteger requests = new AtomicInteger();
    private volatile Instant clock;
    private HttpServer server;

    public TestTsa() {
        this("CN=jip test TSA", Instant.now().minus(Duration.ofDays(1)), Instant.now().plus(Duration.ofDays(365)));
    }

    /** A TSA whose certificate is valid from {@code notBefore} to {@code notAfter}. */
    public TestTsa(String subject, Instant notBefore, Instant notAfter) {
        try {
            caKeys = rsa();
            tsaKeys = rsa();
            X500Name caName = new X500Name("CN=jip test CA");
            X509v3CertificateBuilder ca = new JcaX509v3CertificateBuilder(caName, BigInteger.ONE,
                    Date.from(notBefore.minus(Duration.ofDays(1))), Date.from(notAfter.plus(Duration.ofDays(1))), caName, caKeys.getPublic());
            ca.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            ca.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
            caCert = convert(ca);

            X509v3CertificateBuilder tsa = new JcaX509v3CertificateBuilder(caName, BigInteger.TWO,
                    Date.from(notBefore), Date.from(notAfter), new X500Name(subject), tsaKeys.getPublic());
            tsa.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            tsa.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            tsa.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));
            tsaCert = convert(tsa);
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    /** The CA as a trust anchor. */
    public Set<TrustAnchor> anchors() {
        return Set.of(new TrustAnchor(caCert, null));
    }

    public X509Certificate caCertificate() {
        return caCert;
    }

    /** Use a fixed time for the tokens (null: now). */
    public TestTsa at(Instant time) {
        this.clock = time;
        return this;
    }

    /** Number of HTTP requests answered so far. */
    public int requests() {
        return requests.get();
    }

    /** A token for a SHA-256 imprint, as a TSA would issue it (no request round trip). */
    public byte[] token(byte[] imprint) {
        try {
            TimeStampRequest req = Rfc3161.request(imprint, BigInteger.valueOf(42));
            return Rfc3161.tokenFromReply(req, reply(req.getEncoded()));
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    /** The DER reply to a DER request. */
    public byte[] reply(byte[] request) throws Exception {
        TimeStampRequest req = new TimeStampRequest(request);
        Date t = Date.from(clock == null ? Instant.now() : clock);
        // A real TSA's CMS signingTime is its genTime; pin it to the (possibly fixed) clock.
        AttributeTable signingTime = new AttributeTable(new Attribute(CMSAttributes.signingTime, new DERSet(new Time(t))));
        TimeStampTokenGenerator gen = new TimeStampTokenGenerator(
                new JcaSimpleSignerInfoGeneratorBuilder()
                        .setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(signingTime))
                        .build("SHA256withRSA", tsaKeys.getPrivate(), tsaCert),
                new JcaDigestCalculatorProviderBuilder().build().get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)),
                POLICY);
        gen.addCertificates(new JcaCertStore(List.of(tsaCert, caCert)));
        TimeStampResponseGenerator resp = new TimeStampResponseGenerator(gen, TSPAlgorithms.ALLOWED);
        return resp.generateGrantedResponse(req, BigInteger.valueOf(serial.getAndIncrement()), t).getEncoded();
    }

    /** Start an HTTP endpoint; returns its URI. */
    public URI start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/tsa", exchange -> {
            requests.incrementAndGet();
            try ( InputStream in = exchange.getRequestBody(); OutputStream out = exchange.getResponseBody() ) {
                byte[] body;
                try {
                    body = reply(in.readAllBytes());
                } catch (Exception ex) {
                    exchange.sendResponseHeaders(400, -1);
                    return;
                }
                exchange.getResponseHeaders().add("Content-Type", Rfc3161.MEDIA_TYPE_REPLY);
                exchange.sendResponseHeaders(200, body.length);
                out.write(body);
            }
        });
        server.start();
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/tsa");
    }

    @Override
    public void close() {
        if ( server != null )
            server.stop(0);
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair();
    }

    private X509Certificate convert(X509v3CertificateBuilder b) throws Exception {
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withRSA").build(caKeys.getPrivate())));
    }
}
