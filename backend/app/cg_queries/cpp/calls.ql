/**
 * Resolved call edges for C/C++: (enclosing Function) -> (target Function).
 * @id veriaudit/cg-calls-cpp
 * @kind table
 */
import cpp
from FunctionCall call, Function caller, Function callee
where caller = call.getEnclosingFunction() and callee = call.getTarget()
  and caller.hasDefinition() and callee.hasDefinition()
select caller.getLocation().getFile().getRelativePath(), caller.getLocation().getStartLine(), caller.getName(),
       callee.getLocation().getFile().getRelativePath(), callee.getLocation().getStartLine(), callee.getName(),
       call.getLocation().getStartLine()
