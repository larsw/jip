package xyz.larsw.jip.function;

import org.apache.jena.query.QueryBuildException;
import org.apache.jena.sparql.engine.binding.Binding;
import org.apache.jena.sparql.expr.ExprList;
import org.apache.jena.sparql.expr.NodeValue;
import org.apache.jena.sparql.function.Function;
import org.apache.jena.sparql.function.FunctionEnv;
import org.apache.jena.sparql.util.Context;
import xyz.larsw.jip.version.DataVersion;

/**
 * {@code jip:tdbDataVersion()}: TDB2's internal {@code TransactionCoordinator.dataVersion} as
 * seen by the current transaction. Monotonic within one JVM run, reset to 0 on restart.
 * Exposed for comparison with the persistent {@code jip:dataVersion()}.
 */
public class TdbDataVersionFunction implements Function {

    @Override
    public void build(String uri, ExprList args, Context context) {
        if ( !args.isEmpty() )
            throw new QueryBuildException("jip:tdbDataVersion() takes no arguments");
    }

    @Override
    public NodeValue exec(Binding binding, ExprList args, String uri, FunctionEnv env) {
        return NodeValue.makeInteger(DataVersion.tdbInternalVersion(env.getDataset()));
    }
}
