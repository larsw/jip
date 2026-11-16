package org.example.jena.provenance.canon;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFParser;
import org.apache.jena.riot.lang.LabelToNode;
import org.apache.jena.sparql.core.DatasetGraph;
import org.apache.jena.sparql.core.DatasetGraphFactory;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/**
 * Runs the official W3C RDF Dataset Canonicalization test suite (vendored from
 * https://github.com/w3c/rdf-canon, see src/test/resources/w3c/rdf-canon/SOURCE) through the
 * Jena adapter: parse with Jena, canonicalize via titanium-rdfc, compare byte for byte.
 */
class RdfCanonW3CTest {

    private static final String BASE = "/w3c/rdf-canon/";
    private static final long NEGATIVE_TEST_LIMIT_MILLIS = 3_000;

    record Entry(String id, String name, String hashAlgorithm, String type, boolean mapTest) {}

    @TestFactory
    Stream<DynamicTest> w3cSuite() throws IOException {
        List<Entry> entries = manifest();
        assertTrue(entries.size() > 60, "manifest loaded");
        return entries.stream().map(e -> DynamicTest.dynamicTest(e.id() + " " + e.name(), () -> run(e)));
    }

    private void run(Entry e) throws IOException {
        String alg = "SHA384".equals(e.hashAlgorithm()) ? "SHA-384" : "SHA-256";
        DatasetGraph input = parse(e.id() + "-in.nq");

        if ( e.type().equals("RDFC10NegativeEvalTest") ) {
            RdfCanonicalizer canon = RdfCanonicalizer.create(alg, NEGATIVE_TEST_LIMIT_MILLIS, true);
            assertThrows(IllegalStateException.class, () -> canon.canonicalizeWithMapping(input.find()),
                         "poison graph must be rejected within the limit");
            return;
        }
        assertEquals("TRUE", e.type(), "unknown test type " + e.type());

        RdfCanonicalizer canon = RdfCanonicalizer.create(alg, RdfCanonicalizer.DEFAULT_TIME_LIMIT_MILLIS, true);
        RdfCanonicalizer.Result result = canon.canonicalizeWithMapping(input.find());
        String expected = read(e.id() + "-rdfc10.nq");
        assertEquals(expected, result.canonicalNQuads());

        if ( e.mapTest() ) {
            Map<String, String> expectedMap = parseFlatJson(read(e.id() + "-rdfc10map.json"));
            Map<String, String> actual = new HashMap<>();
            result.blankNodeMapping().forEach((k, v) -> actual.put(strip(k), strip(v)));
            assertEquals(expectedMap, actual, "blank node mapping");
        }
    }

    private static DatasetGraph parse(String file) throws IOException {
        DatasetGraph dsg = DatasetGraphFactory.createGeneral();
        try ( InputStream in = resource(file) ) {
            RDFParser.source(in).lang(Lang.NQUADS)
                    .labelToNode(LabelToNode.createUseLabelAsGiven())
                    .parse(dsg);
        }
        return dsg;
    }

    private static List<Entry> manifest() throws IOException {
        List<Entry> entries = new ArrayList<>();
        List<List<String>> rows = parseCsv(read("manifest.csv"));
        List<String> header = rows.get(0);
        int iTest = header.indexOf("test"), iName = header.indexOf("name"), iHash = header.indexOf("hashAlgorithm"),
                iType = header.indexOf("rdfc10"), iMap = header.indexOf("rdfc10map");
        for ( List<String> r : rows.subList(1, rows.size()) ) {
            if ( r.size() <= iMap || r.get(iTest).isBlank() )
                continue;
            entries.add(new Entry(r.get(iTest), r.get(iName), r.get(iHash), r.get(iType), "TRUE".equals(r.get(iMap))));
        }
        return entries;
    }

    /** Minimal RFC 4180 CSV (quoted fields, doubled quotes, newlines inside quotes). */
    static List<List<String>> parseCsv(String text) {
        List<List<String>> rows = new ArrayList<>();
        List<String> row = new ArrayList<>();
        StringBuilder field = new StringBuilder();
        boolean quoted = false;
        for ( int i = 0 ; i < text.length() ; i++ ) {
            char c = text.charAt(i);
            if ( quoted ) {
                if ( c == '"' && i + 1 < text.length() && text.charAt(i + 1) == '"' ) {
                    field.append('"');
                    i++;
                } else if ( c == '"' ) {
                    quoted = false;
                } else {
                    field.append(c);
                }
            } else if ( c == '"' ) {
                quoted = true;
            } else if ( c == ',' ) {
                row.add(field.toString());
                field.setLength(0);
            } else if ( c == '\n' ) {
                row.add(field.toString());
                field.setLength(0);
                rows.add(row);
                row = new ArrayList<>();
            } else if ( c != '\r' ) {
                field.append(c);
            }
        }
        if ( field.length() > 0 || !row.isEmpty() ) {
            row.add(field.toString());
            rows.add(row);
        }
        return rows;
    }

    private static Map<String, String> parseFlatJson(String json) {
        Map<String, String> map = new HashMap<>();
        Matcher m = Pattern.compile("\"([^\"]+)\"\\s*:\\s*\"([^\"]+)\"").matcher(json);
        while ( m.find() )
            map.put(m.group(1), m.group(2));
        return map;
    }

    private static String strip(String label) {
        return label.startsWith("_:") ? label.substring(2) : label;
    }

    private static String read(String file) throws IOException {
        try ( InputStream in = resource(file) ) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static InputStream resource(String file) {
        String path = BASE + (file.startsWith("test") ? "rdfc10/" : "") + file;
        InputStream in = RdfCanonW3CTest.class.getResourceAsStream(path);
        assertNotNull(in, "missing test resource " + path);
        return in;
    }
}
