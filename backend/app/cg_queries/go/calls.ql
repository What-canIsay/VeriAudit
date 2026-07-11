/**
 * Resolved call edges for Go: (enclosing Callable) -> (target Function decl).
 * @id veriaudit/cg-calls-go
 * @kind table
 */
import go
from DataFlow::CallNode call, Callable caller, FuncDecl callee
where caller = call.getEnclosingCallable() and callee.getFunction() = call.getTarget()
select caller.getLocation().getFile().getRelativePath(), caller.getLocation().getStartLine(), caller.getName(),
       callee.getLocation().getFile().getRelativePath(), callee.getLocation().getStartLine(), callee.getName(),
       call.getLocation().getStartLine()
