package xyz.larsw.jip.canon;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.List;

import org.apache.jena.graph.NodeFactory;
import org.apache.jena.sparql.core.Var;
import org.apache.jena.sparql.engine.binding.Binding;
import org.apache.jena.sparql.engine.binding.BindingBuilder;
import xyz.larsw.jip.service.AttestServiceExecutor;
import org.junit.jupiter.api.Test;

/**
 * Digest time at the default solution cap ({@value AttestServiceExecutor#DEFAULT_MAX_SOLUTIONS} rows),
 * which must stay well inside the canonicalization time limit.
 */
class CanonicalizationCapacityTest {

    static List<Binding> rows(int n, boolean duplicates) {
        List<Binding> rows = new ArrayList<>(n);
        for ( int i = 0 ; i < n ; i++ ) {
            int k = duplicates ? i % 10 : i;
            rows.add(BindingBuilder.create()
                    .add(Var.alloc("s"), NodeFactory.createURI("http://example.org/item/" + k))
                    .add(Var.alloc("label"), NodeFactory.createLiteralString("Item number " + k))
                    .build());
        }
        return rows;
    }

    long time(List<Binding> rows, boolean ordered) {
        ResultSetEncoding.digest(List.of("s", "label"), rows.subList(0, 100), ordered); // warm up
        long start = System.nanoTime();
        ResultSetEncoding.digest(List.of("s", "label"), rows, ordered);
        return (System.nanoTime() - start) / 1_000_000;
    }

    @Test
    void digestAtDefaultCap() {
        int n = AttestServiceExecutor.DEFAULT_MAX_SOLUTIONS;
        long unordered = time(rows(n, false), false);
        long ordered = time(rows(n, false), true);
        long dups = time(rows(n, true), false);
        System.out.printf("[capacity] %d rows x 2 vars: unordered %d ms, ordered %d ms, 10 distinct values repeated %d ms%n",
                          n, unordered, ordered, dups);
        long limit = RdfCanonicalizer.DEFAULT_TIME_LIMIT_MILLIS;
        assertTrue(unordered < limit / 2 && ordered < limit / 2 && dups < limit / 2,
                   "digest at the cap must stay well inside the " + limit + " ms canonicalization limit");
    }
}
