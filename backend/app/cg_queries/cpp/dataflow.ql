/**
 * Taint flow between caller-specified source/sink locations (external predicates). C/C++.
 * @id veriaudit/dataflow-cpp
 */
import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.dataflow.new.TaintTracking
external predicate srcloc(string file, int line);
external predicate snkloc(string file, int line);
predicate isSrc(DataFlow::Node n) { exists(string f, int l | srcloc(f, l) and n.getLocation().getStartLine() = l and n.getLocation().getFile().getRelativePath().matches("%" + f)) }
predicate isSnk(DataFlow::Node n) { exists(string f, int l | snkloc(f, l) and n.getLocation().getStartLine() = l and n.getLocation().getFile().getRelativePath().matches("%" + f)) }
module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isSrc(source) }
  predicate isSink(DataFlow::Node sink) { isSnk(sink) }
}
module Flow = TaintTracking::Global<Cfg>;
from DataFlow::Node a, DataFlow::Node b
where Flow::flow(a, b)
select a.getLocation().getFile().getRelativePath(), a.getLocation().getStartLine(),
       b.getLocation().getFile().getRelativePath(), b.getLocation().getStartLine()
