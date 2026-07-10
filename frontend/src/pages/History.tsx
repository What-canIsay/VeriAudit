import { useCallback, useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { AnimatePresence } from "framer-motion";
import { api } from "../api";
import type { Project, Task } from "../types";
import { fmtElapsed, parseTs } from "../lib/format";
import { VA_CSS, STATUS_LABEL, sevClass } from "../lib/vaTheme";
import { motion, popV, maskV } from "../lib/motion";

const PHASES = ["assess", "plan", "recon", "hunt", "trace", "provision", "verify", "report"];

// History — the audit ledger. Every project is a card; every run is a mono row with its
// outcome, elapsed time and an entry into its console. Live runs carry inline pause/stop.
export default function History() {
  const nav = useNavigate();
  const [projects, setProjects] = useState<Project[]>([]);
  const [cfg, setCfg] = useState<any>(null);
  const [err, setErr] = useState("");
  const [modal, setModal] = useState<null | { mode: "create" | "edit"; id?: string }>(null);

  const load = useCallback(() => api.listProjects().then(setProjects).catch(() => {}), []);
  const [sp, setSp] = useSearchParams();
  useEffect(() => {
    load();
    api.config().then(setCfg).catch(() => {});
    if (sp.get("new") === "1") {
      setModal({ mode: "create" });
      setSp({}, { replace: true });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // keep live runs fresh
  useEffect(() => {
    const anyLive = projects.some((p) => (p.tasks || []).some((t) => ["running", "paused", "queued", "cancelling"].includes(t.status)));
    if (!anyLive) return;
    const t = setInterval(load, 4000);
    return () => clearInterval(t);
  }, [projects, load]);

  async function control(id: string, action: "pause" | "resume" | "cancel") {
    try {
      const fn = action === "pause" ? api.pauseTask : action === "resume" ? api.resumeTask : api.cancelTask;
      await fn(id);
      load();
    } catch (e: any) {
      setErr(String(e.message || e));
    }
  }

  return (
    <div className="va va-hist">
      <style>{VA_CSS + CSS}</style>

      <header className="va-top">
        <div className="va-top-l">
          <button className="va-back va-mark-sm" onClick={() => nav("/")}>← VERIAUDIT</button>
          <span className="va-top-sep" />
          <span className="va-hist-title">审计历史</span>
        </div>
        <button className="va-btn va-btn-line va-btn-sm" onClick={() => setModal({ mode: "create" })}>新建项目</button>
      </header>

      <div className="va-scroll">
        <div className="va-wrap">
          {err && <div className="va-err va-mono" onClick={() => setErr("")}>{err}</div>}

          {projects.length === 0 && (
            <div className="va-card va-empty">
              还没有项目 —— <button className="va-inline" onClick={() => setModal({ mode: "create" })}>新建项目</button> 发起第一次审计。
            </div>
          )}

          <div className="va-cards">
            {projects.map((p, i) => (
              <ProjectCard key={p.id} index={i} p={p} cfg={cfg} nav={nav}
                onControl={control} onEdit={() => setModal({ mode: "edit", id: p.id })}
                onErr={setErr} reload={load} />
            ))}
          </div>
        </div>
      </div>

      <AnimatePresence>
        {modal && (
          <ProjectModal key="modal" mode={modal.mode} id={modal.id} cfg={cfg} projects={projects}
            onClose={() => setModal(null)} onDone={load} nav={nav} />
        )}
      </AnimatePresence>
    </div>
  );
}

function ProjectCard({ p, index, cfg, nav, onControl, onEdit, onErr, reload }: any) {
  const tasks: Task[] = p.tasks || [];
  const files = Object.values(p.languages || {}).reduce((a: number, b: any) => a + (Number(b) || 0), 0);
  const primary = Object.entries(p.languages || {}).sort((a: any, b: any) => b[1] - a[1])[0]?.[0];
  const ref = refShort(p);
  const running = tasks.find((t) => ["running", "paused", "cancelling", "queued"].includes(t.status));
  const tag = projectTag(tasks);

  const [depth, setDepth] = useState("deep");
  const [busy, setBusy] = useState(false);
  const [page, setPage] = useState(0);
  const PAGE = 4;
  const pages = Math.max(1, Math.ceil(tasks.length / PAGE));
  const shown = tasks.slice(page * PAGE, page * PAGE + PAGE);

  async function startAudit() {
    setBusy(true);
    try {
      const t = await api.createTask(p.id, { depth });
      nav(`/tasks/${t.id}`);
    } catch (e: any) { onErr(String(e.message || e)); }
    finally { setBusy(false); }
  }

  return (
    <motion.section className="va-card va-proj"
      initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay: Math.min(index || 0, 8) * 0.06, ease: [0.22, 1, 0.36, 1] }}>
      <div className="va-proj-head">
        <div className="va-proj-id">
          <button className="va-proj-name" onClick={onEdit} title="编辑项目">{p.name}</button>
          <div className="va-proj-sub va-mono">
            {primary || "—"} · {files} 文件 · {ref}
          </div>
        </div>
        <span className={`va-tag ${tag.cls}`}>
          <span className={`va-tag-dot ${tag.dotCls} ${running ? "va-pulse" : ""}`} />
          {tag.text}
        </span>
      </div>

      <div className="va-tasks">
        {tasks.length === 0 && <div className="va-notask va-mono">暂无审计记录</div>}
        {shown.map((t) => (
          <TaskRow key={t.id} t={t} nav={nav} onControl={onControl} />
        ))}
        {pages > 1 && (
          <div className="va-pager va-mono">
            <button className="va-pg" disabled={page === 0} onClick={() => setPage((p: number) => Math.max(0, p - 1))}>‹</button>
            <span className="va-pg-n">{page + 1} / {pages}</span>
            <button className="va-pg" disabled={page >= pages - 1} onClick={() => setPage((p: number) => Math.min(pages - 1, p + 1))}>›</button>
          </div>
        )}
      </div>

      <div className="va-proj-foot">
        <select className="va-depth va-mono" value={depth} onChange={(e) => setDepth(e.target.value)}>
          <option value="fast">fast</option>
          <option value="standard">standard</option>
          <option value="deep">deep</option>
        </select>
        <button className="va-btn va-btn-line va-btn-sm" disabled={busy || !!running} onClick={startAudit}
          title={running ? "有任务进行中" : ""}>
          {busy ? "启动中…" : "开始审计"} {!busy && <span className="va-arrow">→</span>}
        </button>
      </div>
    </motion.section>
  );
}

function TaskRow({ t, nav, onControl }: { t: Task; nav: any; onControl: any }) {
  const live = ["running", "paused", "cancelling", "queued"].includes(t.status);
  const s = sevClass(worstSev(t));
  const el = elapsed(t);
  const total = t.counts?.total_findings ?? 0;
  const dyn = t.counts?.confirmed_dynamic ?? 0;
  const prog = Math.min(1, (PHASES.indexOf(t.phase) + 1) / PHASES.length);

  return (
    <div className={`va-row ${live ? "live" : ""}`} onClick={() => nav(`/tasks/${t.id}`)} role="button">
      <span className={`va-row-dot ${s.dot} ${t.status === "running" ? "va-pulse" : ""}`} />
      <span className="va-row-depth va-mono">{t.depth}</span>
      <span className="va-row-status va-mono">{STATUS_LABEL[t.status] || t.status}</span>

      <span className="va-row-body va-mono">
        {live ? (
          <span className="va-prog">
            <span className="va-prog-bar"><span className="va-prog-fill" style={{ width: `${prog * 100}%` }} /></span>
            <span className="va-prog-txt">{t.phase || "—"}</span>
          </span>
        ) : t.status === "succeeded" ? (
          <span>{total} findings{dyn ? ` (${dyn} 复现)` : ""}</span>
        ) : (
          <span className="va-dim">{total ? `${total} findings · ` : ""}{t.error ? shortErr(t.error) : STATUS_LABEL[t.status]}</span>
        )}
      </span>

      <span className="va-row-time va-mono">
        {live ? (t.status === "paused" ? "已暂停" : "运行中") : (el ? `耗时 ${el}` : "")}
      </span>

      <span className="va-row-act" onClick={(e) => e.stopPropagation()}>
        {t.status === "running" && (
          <>
            <button className="va-iconbtn va-iconbtn-sm" title="暂停" onClick={() => onControl(t.id, "pause")}>❚❚</button>
            <button className="va-iconbtn va-iconbtn-sm" title="停止" onClick={() => onControl(t.id, "cancel")}>■</button>
          </>
        )}
        {t.status === "paused" && (
          <>
            <button className="va-iconbtn va-iconbtn-sm" title="继续" onClick={() => onControl(t.id, "resume")}>▶</button>
            <button className="va-iconbtn va-iconbtn-sm" title="停止" onClick={() => onControl(t.id, "cancel")}>■</button>
          </>
        )}
        {!live && (
          <button className="va-open va-mono" onClick={() => nav(`/tasks/${t.id}`)}>
            {t.status === "succeeded" ? "报告" : "打开"} <span className="va-arrow">→</span>
          </button>
        )}
      </span>
    </div>
  );
}

function ProjectModal({ mode, id, cfg, projects, onClose, onDone, nav }: any) {
  const existing: Project | undefined = projects.find((p: Project) => p.id === id);
  const [name, setName] = useState(existing?.name || "");
  const [stype, setStype] = useState(existing?.source_type || "git_url");
  const [ref, setRef] = useState(existing?.source_ref || "");
  const [depth, setDepth] = useState("deep");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr(""); setBusy(true);
    try {
      if (mode === "edit" && id) {
        await api.updateProject(id, { name, source_type: stype, source_ref: ref });
        onDone(); onClose();
      } else {
        const p = await api.createProject({ name: name || "未命名项目", source_type: stype, source_ref: ref });
        onDone();
        const t = await api.createTask(p.id, { depth });
        nav(`/tasks/${t.id}`);
      }
    } catch (e: any) {
      setErr(String(e.message || e));
    } finally { setBusy(false); }
  }

  function useSample() {
    if (!cfg?.sample_path) return;
    setName("内置漏洞样本 (Flask)"); setStype("local_path"); setRef(cfg.sample_path);
  }

  return (
    <>
      <motion.div className="va-mask" variants={maskV} initial="hidden" animate="show" exit="exit" onClick={onClose} />
      <div className="va-modal">
        <motion.form className="va-card va-modal-card" variants={popV} initial="hidden" animate="show" exit="exit" onSubmit={submit}>
          <div className="va-modal-head">
            <span className="va-modal-title">{mode === "edit" ? "编辑项目" : "新建项目"}</span>
            <button type="button" className="va-x" onClick={onClose}>✕</button>
          </div>
          <div className="va-modal-body">
            {err && <div className="va-err va-mono">{err}</div>}
            <label className="va-field">
              <span className="va-flabel">项目名称</span>
              <input className="va-input" value={name} onChange={(e) => setName(e.target.value)} placeholder="my-service" />
            </label>
            <label className="va-field">
              <span className="va-flabel">来源类型</span>
              <div className="va-seg">
                <button type="button" className={`va-seg-b ${stype === "git_url" ? "on" : ""}`} onClick={() => setStype("git_url")}>Git URL</button>
                <button type="button" className={`va-seg-b ${stype === "local_path" ? "on" : ""}`} onClick={() => setStype("local_path")}>本地路径</button>
              </div>
            </label>
            <label className="va-field">
              <span className="va-flabel">{stype === "git_url" ? "仓库 URL" : "本地绝对路径"}</span>
              <input className="va-input va-mono" value={ref} onChange={(e) => setRef(e.target.value)} required
                placeholder={stype === "git_url" ? "https://github.com/org/repo" : "D:\\path\\to\\project"} />
            </label>
            {mode === "create" && (
              <label className="va-field">
                <span className="va-flabel">审计深度</span>
                <div className="va-seg">
                  {["fast", "standard", "deep"].map((d) => (
                    <button type="button" key={d} className={`va-seg-b va-mono ${depth === d ? "on" : ""}`} onClick={() => setDepth(d)}>{d}</button>
                  ))}
                </div>
              </label>
            )}
            {mode === "edit" && (
              <div className="va-hint va-mono">修改来源后将重新载入代码库快照；审计深度在每次开始审计时选择。</div>
            )}
          </div>
          <div className="va-modal-foot">
            {mode === "create" && cfg?.sample_path && (
              <button type="button" className="va-btn va-btn-line va-btn-sm" onClick={useSample}>内置样本</button>
            )}
            <div className="va-spacer" />
            <button type="button" className="va-btn va-btn-line va-btn-sm" onClick={onClose}>取消</button>
            <button type="submit" className="va-btn va-btn-solid va-btn-sm" disabled={busy}>
              {busy ? "处理中…" : mode === "edit" ? "保存" : "创建并开始"}
            </button>
          </div>
        </motion.form>
      </div>
    </>
  );
}

// ---- derivations ----
function refShort(p: Project) {
  if (p.commit_sha) return `#${p.commit_sha.slice(0, 7)}`;
  const r = p.source_ref || "";
  const base = r.replace(/[\/\\]+$/, "").split(/[\/\\]/).pop() || r;
  return base.replace(/\.git$/, "") || "—";
}
function worstSev(t: Task): string {
  const b = t.counts?.by_severity || {};
  for (const k of ["critical", "high", "medium", "low", "info"]) if (b[k]) return k;
  return "info";
}
function projectTag(tasks: Task[]) {
  const running = tasks.find((t) => ["running", "paused", "queued", "cancelling"].includes(t.status));
  if (running) return { text: "进行中", cls: "t-ok", dotCls: "sd-info" };
  const latest = tasks[0];
  if (!latest) return { text: "无记录", cls: "t-mute", dotCls: "sd-info" };
  const b = latest.counts?.by_severity || {};
  if (b.critical) return { text: "存在严重", cls: "t-crit", dotCls: "sd-critical" };
  if (b.high) return { text: "存在高危", cls: "t-high", dotCls: "sd-high" };
  if (latest.counts?.suspected) return { text: "需要复核", cls: "t-med", dotCls: "sd-medium" };
  if (latest.status === "succeeded") return { text: "低风险", cls: "t-low", dotCls: "sd-low" };
  return { text: STATUS_LABEL[latest.status] || latest.status, cls: "t-mute", dotCls: "sd-info" };
}
function elapsed(t: Task): string {
  const a = parseTs(t.started_at), b = parseTs(t.finished_at);
  if (a == null || b == null) return "";
  return fmtElapsed(b - a);
}
function shortErr(e: string) {
  return e.length > 40 ? e.slice(0, 40) + "…" : e;
}

const CSS = `
/* fixed-viewport shell with an inner scroll region (mirrors TaskConsole) so the document
   itself never scrolls — a full-height document scroll with a height-constrained body was
   failing to repaint the scrolled region (blank/white page). */
.va-hist { height:100dvh; display:flex; flex-direction:column; overflow:hidden; }
.va-top { flex:0 0 auto; height:64px; display:flex; align-items:center; justify-content:space-between;
  padding:0 clamp(24px,3vw,48px); border-bottom:1px solid var(--hair); background:var(--panel); }
.va-top-l { display:flex; align-items:center; gap:16px; min-width:0; }
.va-top-sep { width:1px; height:20px; background:var(--hair); }
.va-hist-title { font-family:'Space Grotesk',sans-serif; font-weight:700; font-size:20px; letter-spacing:.01em; }
.va-back { background:none; border:none; cursor:pointer; letter-spacing:.12em; white-space:nowrap; }
.va-back:hover { color:var(--signal); }
.va-scroll { flex:1 1 auto; min-height:0; overflow-y:auto; }
.va-wrap { max-width:1720px; margin:0 auto; padding:24px clamp(24px,3vw,48px) 72px; }
.va-err { color:var(--crit); border:1px solid var(--crit); background:#FBEDEB; padding:8px 12px;
  font-size:12px; margin-bottom:16px; cursor:pointer; }
.va-empty { padding:40px; text-align:center; color:var(--muted); }
.va-inline { font:inherit; color:var(--signal); background:none; border:none; padding:0; cursor:pointer;
  text-decoration:underline; text-underline-offset:2px; }

.va-cards { display:grid; grid-template-columns:repeat(2, minmax(0,1fr)); gap:18px; align-items:stretch; }
.va-proj { padding:0; display:flex; flex-direction:column; }
.va-proj-head { display:flex; align-items:flex-start; justify-content:space-between; gap:16px;
  padding:20px 22px 14px; }
.va-proj-name { font-family:'IBM Plex Sans',sans-serif; font-weight:700; font-size:18px; color:var(--ink);
  background:none; border:none; padding:0; cursor:pointer; text-align:left; }
.va-proj-name:hover { color:var(--signal); }
.va-proj-sub { font-size:12px; color:var(--faint); margin-top:4px; }

.va-tag { display:inline-flex; align-items:center; gap:7px; font-size:12px; padding:5px 11px;
  border:1px solid var(--hair); background:#fff; white-space:nowrap; }
.va-tag-dot { width:7px; height:7px; border-radius:50%; flex:none; }
.t-crit { color:var(--crit); border-color:rgba(184,50,39,.3); }
.t-high { color:var(--high); border-color:rgba(193,106,34,.3); }
.t-med { color:var(--med); border-color:rgba(156,122,26,.3); }
.t-low { color:var(--low); border-color:rgba(78,119,168,.3); }
.t-ok { color:var(--signal); border-color:rgba(11,138,99,.3); }
.t-mute { color:var(--faint); }

.va-tasks { border-top:1px solid var(--hair2); flex:1 1 auto; }
.va-notask { padding:16px 22px; color:var(--faint); font-size:12px; }
.va-pager { display:flex; align-items:center; justify-content:center; gap:14px; padding:10px 22px; }
.va-pg { width:26px; height:26px; border:1px solid var(--hair); background:#fff; color:var(--ink);
  cursor:pointer; border-radius:0; font-size:13px; line-height:1; }
.va-pg:hover:not(:disabled) { background:var(--paper); }
.va-pg:disabled { opacity:.35; cursor:default; }
.va-pg-n { font-size:12px; color:var(--muted); }
.va-row { display:flex; align-items:center; gap:16px; padding:13px 22px; cursor:pointer;
  border-bottom:1px solid var(--hair2); transition:background .12s; }
.va-row:last-child { border-bottom:none; }
.va-row:hover { background:var(--panel2); }
.va-row.live { box-shadow:inset 3px 0 0 var(--signal); }
.va-row-dot { width:8px; height:8px; border-radius:50%; flex:none; }
.va-row-depth { font-size:13px; color:var(--ink); width:64px; flex:none; }
.va-row-status { font-size:13px; color:var(--muted); width:72px; flex:none; }
.va-row-body { font-size:13px; color:var(--ink); flex:1 1 auto; min-width:0; }
.va-row-time { font-size:12.5px; color:var(--faint); white-space:nowrap; }
.va-row-act { display:flex; align-items:center; gap:8px; min-width:64px; justify-content:flex-end; }
.va-prog { display:inline-flex; align-items:center; gap:10px; }
.va-prog-bar { width:180px; max-width:32vw; height:6px; background:var(--hair); overflow:hidden; }
.va-prog-fill { display:block; height:100%; background:var(--signal); transition:width .4s; }
.va-prog-txt { color:var(--signal); font-size:12px; }
.va-iconbtn-sm { width:28px; height:28px; font-size:11px; line-height:1; }
.va-open { background:none; border:none; cursor:pointer; color:var(--signal); font-size:13px; font-weight:600;
  display:inline-flex; align-items:center; gap:6px; padding:0; }
.va-open:hover { text-decoration:underline; text-underline-offset:2px; }

.va-proj-foot { display:flex; align-items:center; gap:10px; justify-content:flex-end;
  padding:12px 22px; border-top:1px solid var(--hair2); }
.va-depth { font-size:12px; padding:7px 10px; border:1px solid var(--hair); background:#fff; color:var(--ink); border-radius:0; }

/* modal */
.va-mask { position:fixed; inset:0; background:rgba(20,24,27,.28); backdrop-filter:blur(2px); z-index:40; }
.va-modal { position:fixed; inset:0; display:grid; place-items:center; z-index:50; padding:24px; pointer-events:none; }
.va-modal-card { width:100%; max-width:520px; pointer-events:auto; background:var(--panel); }
.va-modal-head { display:flex; align-items:center; justify-content:space-between; padding:16px 20px; border-bottom:1px solid var(--hair); }
.va-modal-title { font-weight:700; font-size:16px; }
.va-x { background:none; border:none; cursor:pointer; color:var(--faint); font-size:14px; }
.va-x:hover { color:var(--ink); }
.va-modal-body { padding:20px; display:flex; flex-direction:column; gap:16px; }
.va-field { display:flex; flex-direction:column; gap:7px; }
.va-flabel { font-family:'JetBrains Mono',monospace; font-size:11px; letter-spacing:.1em; text-transform:uppercase; color:var(--faint); }
.va-input { width:100%; border:1px solid var(--hair); background:#fff; padding:10px 12px; font-size:14px; color:var(--ink); border-radius:0; }
.va-input:focus { outline:none; border-color:var(--signal); }
.va-seg { display:flex; gap:8px; }
.va-seg-b { flex:1; padding:9px 12px; border:1px solid var(--hair); background:#fff; color:var(--muted); cursor:pointer; font-size:13px; border-radius:0; }
.va-seg-b.on { border-color:var(--ink); color:var(--ink); font-weight:600; }
.va-hint { font-size:11px; color:var(--faint); }
.va-modal-foot { display:flex; align-items:center; gap:10px; padding:16px 20px; border-top:1px solid var(--hair); }
.va-spacer { flex:1; }

@media (max-width:900px) {
  .va-cards { grid-template-columns:1fr; }
}
@media (max-width:640px) {
  .va-row { flex-wrap:wrap; gap:8px 12px; }
  .va-row-body { order:5; width:100%; }
  .va-prog-bar { width:60vw; max-width:none; }
}
`;
