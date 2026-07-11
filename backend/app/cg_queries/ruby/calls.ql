/**
 * Resolved call edges for Ruby (best-effort; Ruby dispatch is dynamic).
 * @id veriaudit/cg-calls-ruby
 * @kind table
 */
import ruby
import codeql.ruby.DataFlow
import codeql.ruby.ApiGraphs
from DataFlow::CallNode call, DataFlow::MethodNode caller, DataFlow::MethodNode callee
where call.getExprNode().getExpr().getEnclosingMethod() = caller.asCallableAstNode()
  and callee = call.getATarget()
select caller.getLocation().getFile().getRelativePath(), caller.getLocation().getStartLine(), caller.getMethodName(),
       callee.getLocation().getFile().getRelativePath(), callee.getLocation().getStartLine(), callee.getMethodName(),
       call.getLocation().getStartLine()
