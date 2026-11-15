package org.example.jena.provenance.sys;

import org.apache.jena.sparql.core.assembler.AssemblerUtils;
import org.apache.jena.sparql.function.FunctionRegistry;
import org.apache.jena.sys.JenaSubsystemLifecycle;
import org.example.jena.provenance.JIP;
import org.example.jena.provenance.function.DataVersionFunction;
import org.example.jena.provenance.function.TdbDataVersionFunction;
import org.example.jena.provenance.version.VersionedDatasetAssembler;

/**
 * Jena subsystem initialization (via {@code META-INF/services}): registers the
 * {@code jip:VersionedDatasetTDB2} assembler, the SPARQL functions and the certify SERVICE.
 */
public class InitJIP implements JenaSubsystemLifecycle {

    private static volatile boolean initialized = false;

    @Override
    public void start() {
        init();
    }

    public static synchronized void init() {
        if ( initialized )
            return;
        initialized = true;
        AssemblerUtils.registerDataset(JIP.VersionedDatasetTDB2, new VersionedDatasetAssembler());
        FunctionRegistry.get().put(JIP.FN_DATA_VERSION, DataVersionFunction.class);
        FunctionRegistry.get().put(JIP.FN_TDB_DATA_VERSION, TdbDataVersionFunction.class);
    }

    @Override
    public void stop() {}

    @Override
    public int level() {
        // After ARQ and TDB2.
        return 900;
    }
}
