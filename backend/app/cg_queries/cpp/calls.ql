/**
 * Resolved call edges for C/C++: (enclosing Function) -> (target Function).
 *
 * Scoped to the project's CORE sources. Excluded:
 *  - external/library headers (relative path contains ".." — outside the source root);
 *  - example / test / doc / fuzz / script / sample / benchmark trees. Those are commonly
 *    MANY standalone programs (each with its own main() and duplicate helper names)
 *    compiled into one DB, which makes FunctionCall.getTarget() ambiguous and explodes
 *    the edge set with spurious cross-program edges (curl: 40M → 12.8k). Reachability for
 *    files in those trees falls back to the Tree-sitter engine.
 * @id veriaudit/cg-calls-cpp
 * @kind table
 */
import cpp

/** A source file that belongs to the project's core (not a library header nor a
 *  standalone example/test/doc program tree). `p` is a project-relative path, always
 *  bound by the caller (bindingset), so the negative filters below are allowed. */
bindingset[p]
private predicate coreFile(string p) {
  not p.matches("%..%") and
  not p.regexpMatch("(?i)(.*/)?(docs?|examples?|tests?|testing|fuzz|fuzzing|scripts?|samples?|benchmarks?)/.*")
}

from FunctionCall call, Function caller, Function callee, string cf, string ef
where caller = call.getEnclosingFunction() and callee = call.getTarget()
  and caller.hasDefinition() and callee.hasDefinition()
  and cf = caller.getLocation().getFile().getRelativePath()
  and ef = callee.getLocation().getFile().getRelativePath()
  and coreFile(cf) and coreFile(ef)
select cf, caller.getLocation().getStartLine(), caller.getName(),
       ef, callee.getLocation().getStartLine(), callee.getName(),
       call.getLocation().getStartLine()
