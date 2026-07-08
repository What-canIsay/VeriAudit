import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  Plus, Play, FolderGit2, GitBranch, HardDrive, Sparkles, Loader2, Pencil,
  History, ChevronRight,
} from "lucide-react";
import { api } from "../api";
import type { Project, Task } from "../types";
import { shortTime } from "../lib/format";

export default function Projects() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [cfg, setCfg] = useState<any>(null);
  const [form, setForm] = useState<null | { mode: "create" | "edit"; id?: string }>(null);
  const [err, setErr] = useState("");

  const load = () => api.listProjects().then(setProjects).catch(() => {});
  useEffect(() => {
    load();
    api.config().then(setCfg).catch(() => {});
  }, []);

  const [name, setName] = useState("");
  const [stype, setStype] = useState("git_url");
  const [ref, setRef] = useState("");
  const [depth, setDepth] = useState("standard");
  const [busy, setBusy] = useState(false);
  const nav = useNavigate();

  function openCreate() {
    setName(""); setStype("git_url"); setRef(""); setDepth("standard");
    setErr(""); setForm({ mode: "create" });
  }
  function openEdit(p: Project) {
    setName(p.name); setStype(p.source_type); setRef(p.source_ref);
    setErr(""); setForm({ mode: "edit", id: p.id });
  }
  function useSample() {
    if (!cfg?.sample_path) return;
    setName("内置漏洞样本 (Flask)"); setStype("local_path"); setRef(cfg.sample_path);
    setDepth("standard"); setErr(""); setForm({ mode: "create" });
  }

  async function submitForm(e: React.FormEvent) {
    e.preventDefault();
    setErr(""); setBusy(true);
    try {
      if (form?.mode === "edit" && form.id) {
        await api.updateProject(form.id, { name, source_type: stype, source_ref: ref });
        setForm(null); await load();
      } else {
        const p = await api.createProject({ name: name || "未命名项目", source_type: stype, source_ref: ref });
        setForm(null); await load();
        const t = await api.createTask(p.id, { depth });
        nav(`/tasks/${t.id}`);
      }
    } catch (e: any) {
      setErr(String(e.message || e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <header className="h-16 border-b border-border flex items-center justify-between px-6">
        <div>
          <h1 className="text-lg font-semibold">项目</h1>
          <p className="text-xs text-faint">导入代码库，发起多智能体安全审计</p>
        </div>
        <div className="flex items-center gap-2">
          {cfg?.sample_path && (
            <button className="btn-ghost" onClick={useSample}><Sparkles className="w-4 h-4" /> 内置样本</button>
          )}
          <button className="btn-primary" onClick={openCreate}><Plus className="w-4 h-4" /> 新建项目</button>
        </div>
      </header>

      <div className="p-6 space-y-5 max-w-6xl">
        {err && <div className="chip text-critical border-critical/40 bg-critical/10">{err}</div>}

        {form && (
          <form onSubmit={submitForm} className="card p-5 space-y-4 animate-fade-in">
            <div className="text-sm font-medium text-fg">{form.mode === "edit" ? "编辑项目" : "新建项目"}</div>
            <div className="grid md:grid-cols-2 gap-4">
              <Field label="项目名称">
                <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="my-service" />
              </Field>
              <Field label="来源类型">
                <div className="flex gap-2">
                  <TypeBtn active={stype === "git_url"} onClick={() => setStype("git_url")} icon={<GitBranch className="w-4 h-4" />}>Git URL</TypeBtn>
                  <TypeBtn active={stype === "local_path"} onClick={() => setStype("local_path")} icon={<HardDrive className="w-4 h-4" />}>本地路径</TypeBtn>
                </div>
              </Field>
            </div>
            <Field label={stype === "git_url" ? "仓库 URL (http/https)" : "本地绝对路径"}>
              <input className="input font-mono text-xs" value={ref} onChange={(e) => setRef(e.target.value)}
                placeholder={stype === "git_url" ? "https://github.com/org/repo" : "D:\\path\\to\\project"} required />
            </Field>
            {form.mode === "create" && (
              <Field label="审计深度">
                <div className="flex gap-2">
                  {["fast", "standard", "deep"].map((d) => (
                    <TypeBtn key={d} active={depth === d} onClick={() => setDepth(d)}>{d}</TypeBtn>
                  ))}
                </div>
              </Field>
            )}
            {form.mode === "edit" && (
              <div className="text-[11px] text-faint">修改来源/路径后将重新载入代码库快照；审计深度在每次「开始审计」时选择。</div>
            )}
            <div className="flex justify-end gap-2">
              <button type="button" className="btn-ghost" onClick={() => setForm(null)}>取消</button>
              <button type="submit" className="btn-primary" disabled={busy}>
                {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                {form.mode === "edit" ? "保存" : "创建并开始审计"}
              </button>
            </div>
          </form>
        )}

        {projects.length === 0 && !form && (
          <div className="card p-12 text-center">
            <FolderGit2 className="w-10 h-10 text-faint mx-auto mb-3" />
            <div className="text-muted">还没有项目</div>
            <div className="text-xs text-faint mt-1">点击「新建项目」或「内置样本」开始第一次审计</div>
          </div>
        )}

        <div className="grid md:grid-cols-2 gap-4">
          {projects.map((p) => (
            <ProjectCard key={p.id} p={p} onEdit={() => openEdit(p)} onError={setErr} />
          ))}
        </div>
      </div>
    </div>
  );
}

function ProjectCard({ p, onEdit, onError }: { p: Project; onEdit: () => void; onError: (s: string) => void }) {
  const nav = useNavigate();
  const [depth, setDepth] = useState("standard");
  const [busy, setBusy] = useState(false);

  async function startAudit() {
    setBusy(true);
    try {
      const t = await api.createTask(p.id, { depth });
      nav(`/tasks/${t.id}`);
    } catch (e: any) {
      onError(String(e.message || e));
    } finally {
      setBusy(false);
    }
  }

  const tasks = p.tasks || [];
  return (
    <div className="card p-5 hover:border-border-strong transition-colors flex flex-col">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="font-medium truncate">{p.name}</div>
          <div className="text-xs text-faint font-mono truncate mt-0.5">{p.source_ref}</div>
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          <button className="btn-ghost px-2 py-1" title="编辑项目" onClick={onEdit}><Pencil className="w-3.5 h-3.5" /></button>
          <span className="chip text-accent border-accent/30 bg-accent/10">{p.status}</span>
        </div>
      </div>

      <div className="flex flex-wrap gap-1.5 mt-3">
        {Object.entries(p.languages || {}).slice(0, 5).map(([l, n]) => (
          <span key={l} className="chip text-muted border-border">{l} · {n}</span>
        ))}
        {p.commit_sha && <span className="chip text-faint border-border font-mono">#{p.commit_sha}</span>}
      </div>

      {tasks.length > 0 && (
        <div className="mt-4 border-t border-border/60 pt-3">
          <div className="flex items-center gap-1.5 mb-2 text-faint">
            <History className="w-3.5 h-3.5" />
            <span className="text-[11px] uppercase tracking-wider font-mono">历史审计</span>
          </div>
          <div className="space-y-1 max-h-40 overflow-y-auto">
            {tasks.map((t) => <TaskRow key={t.id} t={t} />)}
          </div>
        </div>
      )}

      <div className="flex items-center justify-end gap-2 mt-4">
        <select value={depth} onChange={(e) => setDepth(e.target.value)}
          className="bg-surface-2 border border-border rounded-lg px-2 py-1.5 text-xs text-fg focus:outline-none focus:ring-2 focus:ring-accent/40">
          <option value="fast">fast</option>
          <option value="standard">standard</option>
          <option value="deep">deep</option>
        </select>
        <button className="btn-outline" onClick={startAudit} disabled={busy}>
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
          开始审计
        </button>
      </div>
    </div>
  );
}

function TaskRow({ t }: { t: Task }) {
  const st: Record<string, { t: string; c: string }> = {
    succeeded: { t: "已完成", c: "text-accent" },
    running: { t: "进行中", c: "text-accent" },
    failed: { t: "失败", c: "text-critical" },
    queued: { t: "排队", c: "text-muted" },
  };
  const s = st[t.status] || st.queued;
  const total = t.counts?.total_findings ?? 0;
  const dyn = t.counts?.confirmed_dynamic ?? 0;
  return (
    <Link to={`/tasks/${t.id}`}
      className="flex items-center gap-2 px-2 py-1.5 rounded-lg hover:bg-surface-3/60 transition-colors group">
      <span className={`text-xs ${s.c} w-12 shrink-0`}>{s.t}</span>
      <span className="chip text-faint border-border text-[10px]">{t.depth}</span>
      <span className="text-[11px] text-faint font-mono shrink-0">{shortTime(t.created_at)}</span>
      {["succeeded", "failed"].includes(t.status) && (
        <span className="text-[11px] text-muted truncate">· {total} 漏洞{dyn ? ` · 动态 ${dyn}` : ""}</span>
      )}
      <ChevronRight className="w-3.5 h-3.5 text-faint ml-auto group-hover:text-fg" />
    </Link>
  );
}

function Field({ label, children }: any) {
  return (
    <label className="block">
      <div className="label mb-1.5">{label}</div>
      {children}
    </label>
  );
}

function TypeBtn({ active, onClick, icon, children }: any) {
  return (
    <button type="button" onClick={onClick}
      className={`btn ${active ? "bg-surface-3 text-fg border border-accent/40" : "text-muted border border-border hover:bg-surface-3"}`}>
      {icon}{children}
    </button>
  );
}
