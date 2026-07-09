/**
 * Caller -> callee edges for JavaScript / TypeScript.
 * JS call resolution lives in the data-flow layer: DataFlow::InvokeNode.getACallee()
 * returns the resolved Function; getContainer() is the enclosing function (the caller).
 * 7 columns: callerFile, callerLine, callerName, calleeFile, calleeLine, calleeName, callSiteLine.
 * @id veriaudit/calls-js
 */
import javascript

from DataFlow::InvokeNode call, Function callee, Function caller
where callee = call.getACallee() and caller = call.getContainer()
select caller.getFile().getRelativePath(), caller.getLocation().getStartLine(), caller.getName(),
       callee.getFile().getRelativePath(), callee.getLocation().getStartLine(), callee.getName(),
       call.asExpr().getLocation().getStartLine()
