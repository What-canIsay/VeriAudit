/**
 * Resolved call edges for C#: (enclosing Callable) -> (target Callable).
 * @id veriaudit/cg-calls-csharp
 * @kind table
 */
import csharp
from Call call, Callable caller, Callable callee
where caller = call.getEnclosingCallable() and callee = call.getTarget()
  and caller.fromSource() and callee.fromSource()
select caller.getLocation().getFile().getRelativePath(), caller.getLocation().getStartLine(), caller.getName(),
       callee.getLocation().getFile().getRelativePath(), callee.getLocation().getStartLine(), callee.getName(),
       call.getLocation().getStartLine()
