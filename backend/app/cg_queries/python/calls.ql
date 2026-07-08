/**
 * Resolved call edges: (caller function) -> (callee function), cross-module.
 * @id veriaudit/cg-calls-py
 */
import python
import semmle.python.objects.ObjectAPI

from CallNode call, FunctionValue fv, Function caller, Function callee
where call = fv.getACall()
  and callee = fv.getScope()
  and caller = call.getNode().getScope()
select caller.getLocation().getFile().getRelativePath() as callerFile,
       caller.getLocation().getStartLine() as callerLine,
       caller.getName() as callerName,
       callee.getLocation().getFile().getRelativePath() as calleeFile,
       callee.getLocation().getStartLine() as calleeLine,
       callee.getName() as calleeName
