package xyz.larsw.jip.sys;

import org.apache.jena.sparql.core.assembler.AssemblerUtils;
import org.apache.jena.sparql.function.FunctionRegistry;
import org.apache.jena.sparql.service.ServiceExecutorRegistry;
import org.apache.jena.sys.JenaSubsystemLifecycle;
import xyz.larsw.jip.JIP;
import xyz.larsw.jip.function.DataVersionFunction;
import xyz.larsw.jip.function.TdbDataVersionFunction;
import xyz.larsw.jip.service.CertifyServiceExecutor;
import xyz.larsw.jip.version.VersionedDatasetAssembler;

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
        // Prepended to the chain: runs before the HTTP executor and its httpServiceAllowed check.
        ServiceExecutorRegistry.get().addSingleLink(new CertifyServiceExecutor());
    }

    @Override
    public void stop() {}

    @Override
    public int level() {
        // After ARQ and TDB2.
        return 900;
    }
}
