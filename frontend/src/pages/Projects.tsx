import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Plus, Play, FolderGit2, GitBranch, HardDrive, Sparkles, Loader2 } from "lucide-react";
import { api } from "../api";
import type { Project } from "../types";

export default function Projects() {
  const nav = useNavigate();
  const [projects, setProjects] = useState<Project[]>([]);
  const [cfg, setCfg] = useState<any>(null);
  const [showForm, setShowForm] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
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

  async function createProject(e: React.FormEvent) {
    e.preventDefault();
    setErr("");
    setBusy("create");
    try {
      const p = await api.createProject({ name: name || "未命名项目", source_type: stype, source_ref: ref });
      setShowForm(false);
      setName(""); setRef("");
      await load();
      // auto-start an audit for immediate feedback
      const t = await api.createTask(p.id, { depth });
      nav(`/tasks/${t.id}`);
    } catch (e: any) {
      setErr(String(e.message || e));
    } finally {
      setBusy(null);
    }
  }

  async function startAudit(pid: string) {
    setBusy(pid);
    try {
      const t = await api.createTask(pid, { depth: "standard" });
      nav(`/tasks/${t.id}`);
    } catch (e: any) {
      setErr(String(e.message || e));
    } finally {
      setBusy(null);
    }
  }

  function useSample() {
    if (cfg?.sample_path) {
      setStype("local_path");
      setRef(cfg.sample_path);
      setName("内置漏洞样本 (Flask)");
      setShowForm(true);
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
            <button className="btn-ghost" onClick={useSample}>
              <Sparkles className="w-4 h-4" /> 内置样本
            </button>
          )}
          <button className="btn-primary" onClick={() => setShowForm((v) => !v)}>
            <Plus className="w-4 h-4" /> 新建项目
          </button>
        </div>
      </header>

      <div className="p-6 space-y-5 max-w-6xl">
        {err && <div className="chip text-critical border-critical/40 bg-critical/10">{err}</div>}

        {showForm && (
          <form onSubmit={createProject} className="card p-5 space-y-4 animate-fade-in">
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
            <Field label="审计深度">
              <div className="flex gap-2">
                {["fast", "standard", "deep"].map((d) => (
                  <TypeBtn key={d} active={depth === d} onClick={() => setDepth(d)}>{d}</TypeBtn>
                ))}
              </div>
            </Field>
            <div className="flex justify-end gap-2">
              <button type="button" className="btn-ghost" onClick={() => setShowForm(false)}>取消</button>
              <button type="submit" className="btn-primary" disabled={busy === "create"}>
                {busy === "create" ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                创建并开始审计
              </button>
            </div>
          </form>
        )}

        {projects.length === 0 && !showForm && (
          <div className="card p-12 text-center">
            <FolderGit2 className="w-10 h-10 text-faint mx-auto mb-3" />
            <div className="text-muted">还没有项目</div>
            <div className="text-xs text-faint mt-1">点击「新建项目」或「内置样本」开始第一次审计</div>
          </div>
        )}

        <div className="grid md:grid-cols-2 gap-4">
          {projects.map((p) => (
            <div key={p.id} className="card p-5 hover:border-border-strong transition-colors">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="font-medium truncate">{p.name}</div>
                  <div className="text-xs text-faint font-mono truncate mt-0.5">{p.source_ref}</div>
                </div>
                <span className="chip text-accent border-accent/30 bg-accent/10 shrink-0">{p.status}</span>
              </div>
              <div className="flex flex-wrap gap-1.5 mt-3">
                {Object.entries(p.languages || {}).slice(0, 5).map(([l, n]) => (
                  <span key={l} className="chip text-muted border-border">{l} · {n}</span>
                ))}
                {p.commit_sha && <span className="chip text-faint border-border font-mono">#{p.commit_sha}</span>}
              </div>
              <div className="flex justify-end mt-4">
                <button className="btn-outline" onClick={() => startAudit(p.id)} disabled={busy === p.id}>
                  {busy === p.id ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                  开始审计
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
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
