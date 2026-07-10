import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import type { Project } from "../types";
import { relTime } from "../lib/format";
import { VA_CSS } from "../lib/vaTheme";
import { motion } from "../lib/motion";

const rise = (delay: number) => ({
  initial: { opacity: 0, y: 12 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.55, delay, ease: [0.22, 1, 0.36, 1] as const },
});

// Home — the instrument nameplate. Graph-paper field, a widely-tracked wordmark, the
// signature source→sink trace, two actions, and a low readout of live capability + last run.
export default function Home() {
  const nav = useNavigate();
  const [cfg, setCfg] = useState<any>(null);
  const [projects, setProjects] = useState<Project[]>([]);

  useEffect(() => {
    api.config().then(setCfg).catch(() => {});
    api.listProjects().then(setProjects).catch(() => {});
  }, []);

  const last = projects
    .flatMap((p) => (p.tasks || []).map((t) => ({ ...t, project: p.name })))
    .sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""))[0];

  const s: Record<string, boolean> = cfg?.scanners || {};
  const cg: Record<string, boolean> = cfg?.callgraph || {};
  const caps: [string, boolean][] = [
    ["CodeQL", !!s.codeql],
    ["Joern", !!cg.joern],
    ["Docker", !!cfg?.sandbox_available],
    ["Semgrep", !!s.semgrep],
    ["RAG", !!cfg?.rag_available],
  ];
  const mode = cfg?.mock_mode ? "mock" : "cloud";
  const model = cfg?.model_tiers?.strong || cfg?.llm_provider || "";

  return (
    <div className="va va-home">
      <style>{VA_CSS + CSS}</style>

      <header className="va-top">
        <span className="va-mark-sm">VERIAUDIT</span>
        <span className="va-pill">
          {cfg == null ? (
            <span className="va-dim">连接中…</span>
          ) : (
            <>
              <span className="va-pdot" />
              {mode} · {String(model).replace(/\s+/g, "")}
            </>
          )}
        </span>
      </header>

      <main className="va-hero">
        <motion.h1 className="va-mark" {...rise(0.05)}>VERIAUDIT</motion.h1>
        <motion.div {...rise(0.35)}><Trace /></motion.div>
        <motion.p className="va-tag" {...rise(0.6)}>从发现到复现，每个漏洞都可追溯</motion.p>
        <motion.div className="va-actions" {...rise(0.78)}>
          <motion.button className="va-btn va-btn-solid" whileTap={{ scale: 0.97 }} onClick={() => nav("/history?new=1")}>
            新建项目 <span className="va-arrow">→</span>
          </motion.button>
          <motion.button className="va-btn va-btn-line" whileTap={{ scale: 0.97 }} onClick={() => nav("/history")}>
            审计历史
          </motion.button>
        </motion.div>
      </main>

      <motion.footer className="va-readout" initial={{ opacity: 0 }} animate={{ opacity: 1 }}
        transition={{ duration: 0.6, delay: 1 }}>
        <div className="va-read-left">
          <div className="va-read-row">
            <span className="va-read-label">能力读数</span>
            {caps.map(([k, ok]) => (
              <span key={k} className="va-cap va-mono">
                {k} <span className={ok ? "va-ok" : "va-no"}>{ok ? "✓" : "✗"}</span>
              </span>
            ))}
          </div>
          <div className="va-read-sub va-mono">
            <span className="va-sub-k">模式</span> <span className="va-ok">{mode}</span>
            <span className="va-mid"> · </span>沙箱{" "}
            <span className={cfg?.sandbox_available ? "va-ok" : "va-no"}>
              {cfg?.sandbox_available ? "ready" : "off"}
            </span>
            <span className="va-mid"> · </span>SARIF export <span className="va-ok">ready</span>
            <span className="va-mid"> · </span>SSE stream <span className="va-ok">healthy</span>
          </div>
        </div>

        <div className="va-read-right">
          <div className="va-read-label">最近任务</div>
          {last ? (
            <button className="va-last va-mono" onClick={() => nav(`/tasks/${last.id}`)}>
              <span className="va-last-name">{last.project}</span>
              <span className="va-mid"> · </span>{last.depth}
              <span className="va-mid"> · </span>
              {last.counts?.total_findings ?? 0} findings
              <span className="va-mid"> · </span>{relTime(last.created_at)}
              <span className="va-arrow"> →</span>
            </button>
          ) : (
            <div className="va-dim">暂无审计记录</div>
          )}
        </div>
      </motion.footer>
    </div>
  );
}

// signature: source· ──○────○────● ·sink — drawn on load, all green (respects reduced-motion)
function Trace() {
  return (
    <div className="va-trace" aria-hidden>
      <span className="va-trace-end va-mono">source·</span>
      <svg width="420" height="24" viewBox="0 0 420 24" className="va-trace-svg">
        <line x1="4" y1="12" x2="416" y2="12" className="va-tline" />
        <circle cx="120" cy="12" r="6" className="va-node hollow p1" />
        <circle cx="260" cy="12" r="6" className="va-node hollow p2" />
        <circle cx="410" cy="12" r="6" className="va-node solid p3" />
      </svg>
      <span className="va-trace-end va-mono">·sink</span>
    </div>
  );
}

const CSS = `
.va-home { min-height:100dvh; display:flex; flex-direction:column; }
.va-top { height:60px; flex:0 0 auto; display:flex; align-items:center;
  justify-content:space-between; padding:0 clamp(24px,4vw,44px); }

.va-hero { flex:1 1 auto; display:flex; flex-direction:column; align-items:center;
  justify-content:center; text-align:center; padding:24px 20px; }
.va-mark { font-family:'Space Grotesk',sans-serif; font-weight:700; color:var(--ink);
  font-size:clamp(46px,10.5vw,128px); letter-spacing:.14em; line-height:1; margin:0 0 0 .14em; }
.va-tag { font-size:clamp(15px,1.5vw,19px); color:var(--muted); font-weight:300; margin:26px 0 34px; }

.va-trace { display:flex; align-items:center; gap:10px; margin-top:30px; }
.va-trace-end { font-size:12px; color:var(--faint); }
.va-tline { stroke:var(--signal); stroke-width:1.5; stroke-dasharray:412; stroke-dashoffset:412;
  animation:vaDraw 1.15s cubic-bezier(.4,0,.2,1) .1s forwards; }
.va-node { opacity:0; transform-box:fill-box; transform-origin:center; }
.va-node.hollow { fill:var(--paper); stroke:var(--signal); stroke-width:1.6; }
.va-node.solid { fill:var(--signal); }
.p1 { animation:vaPop .3s ease-out .55s forwards; }
.p2 { animation:vaPop .3s ease-out .82s forwards; }
.p3 { animation:vaPop .35s ease-out 1.12s forwards; }

.va-actions { display:flex; gap:16px; flex-wrap:wrap; justify-content:center; }
.va-home .va-btn { padding:15px 30px; font-size:15px; }

.va-readout { flex:0 0 auto; display:flex; justify-content:space-between; align-items:flex-start;
  gap:32px; border-top:1px solid var(--hair); margin:0 clamp(24px,4vw,44px); padding:26px 0 40px; }
.va-read-label { font-weight:600; font-size:13px; color:var(--ink); }
.va-read-row { display:flex; align-items:baseline; flex-wrap:wrap; gap:16px; }
.va-cap { font-size:13px; color:var(--ink); }
.va-read-sub { font-size:12.5px; color:var(--faint); margin-top:12px; }
.va-sub-k { color:var(--muted); }
.va-read-right { border-left:1px solid var(--hair); padding-left:32px; text-align:left; }
.va-last { background:none; border:none; cursor:pointer; padding:12px 0 0; font-size:12.5px; color:var(--muted); }
.va-last:hover .va-last-name { text-decoration:underline; }
.va-last-name { font-family:'IBM Plex Sans',sans-serif; font-weight:600; color:var(--ink); }
.va-last .va-arrow { color:var(--ink); }

@media (prefers-reduced-motion:reduce) {
  .va-tline { animation:none; stroke-dashoffset:0; }
  .va-node { animation:none; opacity:1; }
}
@media (max-width:720px) {
  .va-readout { flex-direction:column; gap:22px; }
  .va-read-right { border-left:none; padding-left:0; border-top:1px solid var(--hair); padding-top:18px; width:100%; }
  .va-mark { letter-spacing:.1em; }
  .va-actions { width:100%; }
  .va-home .va-btn { flex:1; justify-content:center; }
}
`;
