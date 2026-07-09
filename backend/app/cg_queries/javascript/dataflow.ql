/**
 * Taint data-flow between a caller-specified source location and sink location (JS/TS).
 * Source/sink lines are passed as external predicates (so the query compiles ONCE and
 * is reused for every cg_dataflow query — only the CSV data changes).
 * @id veriaudit/dataflow-js
 */
import javascript

external predicate srcloc(string file, int line);
external predicate snkloc(string file, int line);

predicate isSrc(DataFlow::Node n) {
  exists(string f, int l |
    srcloc(f, l) and
    n.getLocation().getStartLine() = l and
    n.getLocation().getFile().getRelativePath().matches("%" + f))
}

predicate isSnk(DataFlow::Node n) {
  exists(string f, int l |
    snkloc(f, l) and
    n.getLocation().getStartLine() = l and
    n.getLocation().getFile().getRelativePath().matches("%" + f))
}

module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isSrc(source) }
  predicate isSink(DataFlow::Node sink) { isSnk(sink) }
}

module Flow = TaintTracking::Global<Cfg>;

from DataFlow::Node a, DataFlow::Node b
where Flow::flow(a, b)
select a.getLocation().getFile().getRelativePath(),
       a.getLocation().getStartLine(),
       b.getLocation().getFile().getRelativePath(),
       b.getLocation().getStartLine()
