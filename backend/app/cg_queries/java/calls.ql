/**
 * Resolved call edges for Java: (caller Callable) -> (callee Callable).
 * @id veriaudit/cg-calls-java
 * @kind table
 */
import java
from Call call, Callable caller, Callable callee
where caller = call.getCaller() and callee = call.getCallee()
  and caller.fromSource() and callee.fromSource()
select caller.getLocation().getFile().getRelativePath(), caller.getLocation().getStartLine(), caller.getName(),
       callee.getLocation().getFile().getRelativePath(), callee.getLocation().getStartLine(), callee.getName(),
       call.getLocation().getStartLine()
