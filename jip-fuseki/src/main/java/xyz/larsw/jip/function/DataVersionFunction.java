package xyz.larsw.jip.function;

import org.apache.jena.query.QueryBuildException;
import org.apache.jena.sparql.engine.binding.Binding;
import org.apache.jena.sparql.expr.ExprList;
import org.apache.jena.sparql.expr.NodeValue;
import org.apache.jena.sparql.function.Function;
import org.apache.jena.sparql.function.FunctionEnv;
import org.apache.jena.sparql.util.Context;
import xyz.larsw.jip.version.DataVersion;
import xyz.larsw.jip.version.DataVersionComponent;

/**
 * {@code jip:dataVersion()}: the persistent data version of the snapshot the current query
 * reads. Fails the query (not just the expression) if the dataset has no data version.
 * <p>
 * Outside a transaction (TDB2 autocommit: each access runs in its own transaction) there is no
 * single snapshot, so the last committed version is returned.
 */
public class DataVersionFunction implements Function {

    @Override
    public void build(String uri, ExprList args, Context context) {
        if ( !args.isEmpty() )
            throw new QueryBuildException("jip:dataVersion() takes no arguments");
    }

    @Override
    public NodeValue exec(Binding binding, ExprList args, String uri, FunctionEnv env) {
        DataVersionComponent component = DataVersion.require(env.getContext(), env.getDataset());
        long v = component.inTransaction() ? component.currentVersion() : component.committedVersion();
        return NodeValue.makeInteger(v);
    }
}
