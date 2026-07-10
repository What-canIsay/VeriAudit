import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { AnimatePresence } from "framer-motion";
import { api } from "../api";
import type { Finding, Task } from "../types";
import { useTaskEvents, timelineToEvents, type LiveEvent } from "../lib/useTaskEvents";
import { fmtElapsed, parseTs } from "../lib/format";
import { VA_CSS, STATUS_LABEL, sevClass, CONF_LABEL } from "../lib/vaTheme";
import { AnimatedNumber, motion, drawerV, popV, maskV } from "../lib/motion";

const PHASES = ["assess", "plan", "recon", "hunt", "trace", "provision", "verify", "report"];
const PHASE_LABEL: Record<string, string> = {
  assess: "评估", plan: "规划", recon: "侦察", hunt: "发现", trace: "追踪",
  provision: "搭建", verify: "验证", report: "报告",
};
const AGENT_COLOR: Record<string, string> = {
  profiler: "#0E7C9B", planner: "#6D5BD0", recon: "#2E7CC4", hunter: "#C16A22",
  tracer: "#2C8C8C", provisioner: "#C16A22", validator: "#0B8A63", reporter: "#B5487B",
  system: "#5C6560",
};

export default function TaskConsole() {
  const { id } = useParams();
  const nav = useNavigate();
  const [task, setTask] = useState<Task | null>(null);
  const [live, setLive] = useState<boolean | undefined>(undefined);
  const [histEvents, setHistEvents] = useState<LiveEvent[]>([]);
  const { events: liveEvents, status, phase, counts: sseCounts, finished, findingIds } =
    useTaskEvents(id, live === true);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [rejectedCount, setRejectedCount] = useState(0);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [reportOpen, setReportOpen] = useState(false);
  const [nowMs, setNowMs] = useState(Date.now());
  const [busy, setBusy] = useState(false);

  // Pull current findings straight from the DB (not only via live events): surfaces findings
  // confirmed BEFORE the console connected, whose events may be evicted from the bounded SSE log.
  const inFlight = useRef(false);
  const refreshFindings = useCallback(() => {
    if (!id || inFlight.current) return;
    inFlight.current = true;
    Promise.allSettled([
      api.findings(id).then(setFindings),
      api.findings(id, "REJECTED").then((r) => setRejectedCount(r.length)),
    ]).finally(() => { inFlight.current = false; });
  }, [id]);

  useEffect(() => {
    if (!id) return;
    setHistEvents([]);
    api.getTask(id).then((t) => {
      setTask(t);
      const done = ["succeeded", "failed", "cancelled"].includes(t.status);
      setLive(!done);
      refreshFindings();
      if (done) api.timeline(id).then((items) => setHistEvents(timelineToEvents(items, t.status))).catch(() => {});
    });
  }, [id, refreshFindings]);

  useEffect(() => {
    if (!id || live === false) return;
    if (findingIds.length > 0 || finished) refreshFindings();
  }, [id, live, findingIds.length, finished, refreshFindings]);

  useEffect(() => {
    if (!id || live === false || finished) return;
    const t = setInterval(refreshFindings, 6000);
    return () => clearInterval(t);
  }, [id, live, finished, refreshFindings]);

  useEffect(() => {
    if (id && finished) api.getTask(id).then(setTask).catch(() => {});
  }, [id, finished]);

  const startedMs = parseTs(task?.started_at);
  const finishedMs = parseTs(task?.finished_at);
  const terminal = finished || ["succeeded", "failed", "cancelled"].includes(task?.status || "");
  useEffect(() => {
    if (terminal || startedMs == null) return;
    const t = setInterval(() => setNowMs(Date.now()), 1000);
    return () => clearInterval(t);
  }, [terminal, startedMs]);
  const elapsedMs = startedMs == null ? null : (terminal ? (finishedMs ?? nowMs) : nowMs) - startedMs;

  async function doControl(action: "pause" | "resume" | "cancel") {
    if (!id || busy) return;
    setBusy(true);
    try {
      const fn = action === "pause" ? api.pauseTask : action === "resume" ? api.resumeTask : api.cancelTask;
      setTask(await fn(id));
    } catch { /* SSE reflects true state */ }
    finally { setBusy(false); }
  }
  async function openFinding(fid: string) {
    setSelected(await api.finding(fid));
  }

  const events = live === false ? histEvents : liveEvents;
  const liveStatus = live === false ? (task?.status || "succeeded") : (status || task?.status || "running");
  const curPhase = live === false ? "report" : (phase || task?.phase || "plan");

  const derivedCounts = useMemo(() => {
    const by_severity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    let cd = 0, cs = 0, sus = 0;
    for (const f of findings) {
      const lvl = f.severity?.level || "info";
      by_severity[lvl] = (by_severity[lvl] || 0) + 1;
      if (f.confidence === "CONFIRMED_DYNAMIC") cd++;
      else if (f.confidence === "CONFIRMED_STATIC") cs++;
      else if (f.confidence === "SUSPECTED") sus++;
    }
    return { confirmed_dynamic: cd, confirmed_static: cs, suspected: sus,
             total_findings: cd + cs + sus, by_severity, rejected: rejectedCount };
  }, [findings, rejectedCount]);

  const isLiveRunning = live !== false && !finished;
  const counts: any = isLiveRunning ? derivedCounts
    : (live === false ? (task?.counts || {}) : (Object.keys(sseCounts).length ? sseCounts : task?.counts || {}));
  const bys = counts.by_severity || {};

  const notices = useMemo(() => {
    const seen = new Set<string>(); const out: any[] = [];
    for (const e of events) {
      if (e.event !== "degradation.notice") continue;
      const k = (e.data?.mechanism || "") + "|" + (e.data?.detail || "");
      if (seen.has(k)) continue; seen.add(k); out.push(e.data);
    }
    return out;
  }, [events]);

  const canReport = finished || liveStatus === "succeeded";
  const idShort = id ? id.slice(0, 8) : "";

  return (
    <div className="va va-con">
      <style>{VA_CSS + CSS}</style>

      {/* header */}
      <header className="va-top">
        <div className="va-top-l">
          <button className="va-back va-mark-sm" onClick={() => nav("/history")}>← VERIAUDIT</button>
          <span className="va-task-id va-mono">task {idShort}…</span>
          <StatusPill status={liveStatus} />
          {startedMs != null && <span className="va-elapsed va-mono">{fmtElapsed(elapsedMs)}</span>}
        </div>
        <div className="va-top-r">
          {liveStatus === "cancelling" && <span className="va-chip va-pulse">停止中…</span>}
          <button className="va-iconbtn" title={liveStatus === "paused" ? "继续" : "暂停"}
            disabled={busy || !["running", "paused"].includes(liveStatus)}
            onClick={() => doControl(liveStatus === "paused" ? "resume" : "pause")}>
            {liveStatus === "paused" ? "▶" : "❚❚"}
          </button>
          <button className="va-iconbtn" title="停止"
            disabled={busy || !["running", "paused"].includes(liveStatus)}
            onClick={() => doControl("cancel")}>■</button>
          <button className="va-btn va-btn-line va-btn-sm" disabled={!canReport} onClick={() => setReportOpen(true)}>报告</button>
        </div>
      </header>

      {/* phase stepper */}
      <div className="va-steps">
        <div className="va-steps-line" />
        <motion.div className="va-steps-fill"
          initial={{ scaleX: 0 }}
          animate={{ scaleX: liveStatus === "succeeded" ? 1 : Math.max(0, PHASES.indexOf(curPhase)) / (PHASES.length - 1) }}
          transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }} />
        {PHASES.map((p, i) => {
          const done = PHASES.indexOf(curPhase) > i || liveStatus === "succeeded";
          const active = curPhase === p && !["succeeded", "failed", "cancelled"].includes(liveStatus);
          return (
            <div key={p} className="va-step">
              <span className={`va-step-node ${done ? "done" : active ? "active" : ""}`} />
              <span className={`va-step-label ${done || active ? "on" : ""}`}>{PHASE_LABEL[p]}</span>
            </div>
          );
        })}
      </div>

      {/* degradation banner */}
      {notices.length > 0 && (
        <div className="va-degrade">
          <span className="va-degrade-k">能力降级</span>
          {notices.map((n, i) => (
            <span key={i} className="va-degrade-i">
              {i > 0 && <span className="va-mid"> · </span>}
              {n.mechanism}{n.detail ? `（${n.detail}）` : ""}
            </span>
          ))}
          <span className="va-mid"> · </span><span className="va-degrade-note">结果仍会标记置信来源</span>
        </div>
      )}

      {/* stat strip */}
      <div className="va-stats">
        <Stat n={counts.total_findings ?? findings.length} label="确认" tone="" />
        <Stat n={bys.critical ?? 0} label="严重" tone="sv-critical" />
        <Stat n={bys.high ?? 0} label="高危" tone="sv-high" />
        <Stat n={counts.suspected ?? 0} label="疑似" tone="sv-medium" />
        <Stat n={counts.rejected ?? 0} label="排除" tone="va-dim" last />
      </div>

      {/* body split */}
      <div className="va-body">
        <section className="va-panel va-stream">
          <div className="va-panel-head">
            <span className="va-panel-t">智能体执行流</span>
            <span className="va-panel-tag va-mono">
              {isLiveRunning ? <><span className="va-pdot va-pulse" /> SSE live</> : "回放"}
            </span>
          </div>
          <div className="va-panel-body">
            <TraceStream events={events} running={isLiveRunning} />
          </div>
        </section>

        <section className="va-panel va-flist">
          <div className="va-panel-head">
            <span className="va-panel-t">漏洞列表</span>
            <span className="va-panel-tag va-mono">click = 证据链 · {findings.length}</span>
          </div>
          <div className="va-panel-body">
            {findings.length === 0 && (
              <div className="va-flist-empty va-mono">
                {liveStatus === "running" ? "验证中，确认的漏洞将实时出现…" : "暂无确认漏洞"}
              </div>
            )}
            {findings.map((f) => <FindingRow key={f.id} f={f} onClick={() => openFinding(f.id)} />)}
          </div>
        </section>
      </div>

      {liveStatus === "failed" && (
        <div className="va-failbar va-mono">审计失败：{task?.error}</div>
      )}

      <AnimatePresence>
        {selected && <FindingDrawer key="drawer" f={selected} onClose={() => setSelected(null)} />}
      </AnimatePresence>
      <AnimatePresence>
        {reportOpen && id && <ReportSheet key="report" taskId={id} onClose={() => setReportOpen(false)} />}
      </AnimatePresence>
    </div>
  );
}

// ---------- stat ----------
function Stat({ n, label, tone, last }: { n: number; label: string; tone: string; last?: boolean }) {
  return (
    <div className={`va-stat ${last ? "last" : ""}`}>
      <div className={`va-stat-n ${tone}`}><AnimatedNumber value={n} /></div>
      <div className="va-stat-l">{label}</div>
    </div>
  );
}

// ---------- status pill ----------
function StatusPill({ status }: { status: string }) {
  const running = status === "running";
  const tone = ["running", "succeeded"].includes(status) ? "ok"
    : ["failed"].includes(status) ? "bad"
    : ["paused", "cancelling"].includes(status) ? "warn" : "mute";
  return (
    <span className={`va-spill s-${tone}`}>
      {running && <span className="va-pdot va-pulse" />}
      {STATUS_LABEL[status] || status}
    </span>
  );
}

// ---------- execution stream ----------
function TraceStream({ events, running }: { events: LiveEvent[]; running: boolean }) {
  const endRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (running) endRef.current?.scrollIntoView({ block: "end" });
  }, [events.length, running]);

  // walk events, tracking the acting agent so tool lines read "hunter ▸ read_file app.py"
  const rows: React.ReactNode[] = [];
  let agent = "system";
  for (const e of events) {
    const d = e.data || {};
    const t = hhmm(e.ts);
    switch (e.event) {
      case "agent.started":
        agent = d.agent || agent;
        rows.push(<Line key={e.seq} t={t} a={agent}>开始工作 <span className="va-dim">{d.node}</span></Line>);
        break;
      case "agent.finished":
        rows.push(<Line key={e.seq} t={t} a={d.agent || agent}><span className="va-ok">✓</span> 完成工作</Line>);
        break;
      case "task.finished":
        rows.push(<Done key={e.seq} data={d} />);
        break;
      case "tool.invoked":
        rows.push(<Line key={e.seq} t={t} a={agent} tool={d.tool}
          arg={d.args_brief && Object.entries(d.args_brief).map(([k, v]) => `${k}=${v}`).join(" ")} />);
        break;
      case "agent.thinking":
        rows.push(<Note key={e.seq}>思考：{d.text}</Note>);
        break;
      case "agent.reasoning":
        rows.push(<Reason key={e.seq} agent={agent} text={d.text} />);
        break;
      case "agent.llm_output":
        rows.push(<Reason key={e.seq} agent={agent} text={d.text} label="模型输出" mono />);
        break;
      case "assess.ready":
        rows.push(<Budget key={e.seq} profile={d.profile || {}} budget={d.budget || {}} />);
        break;
      case "candidate.recorded":
        rows.push(<Line key={e.seq} t={t} a={agent}>候选 <span className="va-mono">{d.vuln_type}</span>{" "}
          <span className="va-dim va-mono">{d.location?.file}:{d.location?.line}</span></Line>);
        break;
      case "sandbox.poc_attempt":
        rows.push(<Line key={e.seq} t={t} a="validator">sandbox <span className="va-mono">{d.vuln_type}</span>{" "}
          <span className={d.reproduced ? "va-ok" : "va-dim"}>{d.reproduced ? "✓ 复现" : d.attempted ? "未复现" : "跳过"}</span></Line>);
        break;
      case "provision.ready":
        rows.push(<Line key={e.seq} t={t} a="provisioner">环境就绪 <span className="va-dim">端口 {d.port}</span></Line>);
        break;
      case "provision.failed":
        rows.push(<Note key={e.seq}>环境未搭建成功，回落逐候选复现：{d.reason}</Note>);
        break;
      case "preheat.ready":
        rows.push(<Line key={e.seq} t={t} a="provisioner">核验预热就绪</Line>);
        break;
      case "degradation.notice":
        rows.push(<Note key={e.seq} warn>能力降级 · {d.mechanism}：{d.detail}</Note>);
        break;
      case "finding.confirmed":
        rows.push(<Line key={e.seq} t={t} a="validator" ok>✓ 确认 <span className="va-mono">{d.title || d.vuln_type}</span>{" "}
          <span className="va-dim">{d.confidence}</span></Line>);
        break;
      case "finding.rejected":
        rows.push(<Note key={e.seq}>已排除 {d.vuln_type}</Note>);
        break;
      case "task.status":
        if (d.status === "running") rows.push(<Note key={e.seq}>阶段 → {d.phase}</Note>);
        break;
      default: break;
    }
  }

  return (
    <div className="va-stream-list">
      {rows.length === 0 && <div className="va-flist-empty va-mono">{running ? "等待智能体启动…" : "无执行记录"}</div>}
      {rows}
      <div ref={endRef} />
    </div>
  );
}

function Line({ t, a, tool, arg, ok, children }: any) {
  const color = AGENT_COLOR[a] || AGENT_COLOR.system;
  return (
    <div className="va-tl va-fade">
      <span className="va-tl-t va-mono">{t}</span>
      <span className="va-tl-dot" style={{ background: color }} />
      <span className="va-tl-a va-mono" style={{ color }}>{a}</span>
      <span className="va-tl-arrow">▸</span>
      <span className={`va-tl-x ${ok ? "va-ok" : ""}`}>
        {tool ? <><span className="va-mono va-tl-tool">{tool}</span>{arg && <span className="va-mono va-dim"> {arg}</span>}</> : children}
      </span>
    </div>
  );
}
function Note({ children, scroll, mono, warn }: any) {
  return <div className={`va-tl-note ${scroll ? "scroll" : ""} ${mono ? "va-mono" : ""} ${warn ? "warn" : ""}`}>{children}</div>;
}
// model reasoning / output — a bordered, fully-scrollable panel so long thinking is never cut off
function Reason({ agent, text, label = "模型思考", mono }: any) {
  const color = AGENT_COLOR[agent] || AGENT_COLOR.system;
  return (
    <div className="va-reason va-fade">
      <div className="va-reason-h" style={{ color, borderColor: color }}>{agent} · {label}</div>
      <div className={`va-reason-b ${mono ? "va-mono" : ""}`}>{text}</div>
    </div>
  );
}
// terminal marker — the audit as a whole has finished (succeeded / failed / stopped)
function Done({ data }: any) {
  const outcome = data.status
    ? data.status
    : data.error ? "failed" : data.cancelled ? "cancelled" : "succeeded";
  const map: Record<string, { t: string; c: string; mk: string }> = {
    succeeded: { t: "审计完成", c: "ok", mk: "✓" },
    failed: { t: "审计失败", c: "bad", mk: "✕" },
    cancelled: { t: "审计已停止", c: "mute", mk: "■" },
  };
  const m = map[outcome] || map.succeeded;
  const err = typeof data.error === "string" ? data.error : "";
  return (
    <div className={`va-done va-done-${m.c} va-mono va-fade`}>
      <span className="va-done-mk">{m.mk}</span>
      <span>{m.t}{outcome === "failed" && err ? ` · ${err}` : ""}</span>
    </div>
  );
}

// adaptive budget / caps for this run — surfaced in the stream like the deterministic pool
function Budget({ profile, budget }: any) {
  const items: [string, any][] = [
    ["挖掘步数", budget.llm_hunt_steps],
    ["候选上限", budget.max_candidates],
    ["验证上限", budget.max_verify],
    ["LLM 三分类上限", budget.llm_triage_limit],
    ["搭建步数", budget.provisioner_max_steps],
    ["搭建时长", budget.provisioner_timeout_sec && `${budget.provisioner_timeout_sec}s`],
    ["任务时长", budget.task_timeout_sec && `${budget.task_timeout_sec}s`],
  ];
  const shown = items.filter(([, v]) => v != null && v !== false);
  return (
    <div className="va-budget va-fade">
      <div className="va-budget-h">规模评估 · 档位 {profile.tier ?? "—"}</div>
      {profile.rationale && <div className="va-budget-r">{profile.rationale}</div>}
      {shown.length > 0 && (
        <div className="va-budget-chips">
          {shown.map(([k, v]) => (
            <span key={k} className="va-budget-c va-mono"><span className="va-budget-ck">{k}</span> {v}</span>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------- finding row ----------
function FindingRow({ f, onClick }: { f: Finding; onClick: () => void }) {
  const s = sevClass(f.severity?.level);
  const src = f.evidence?.source, sink = f.evidence?.sink;
  const path = src && sink ? `${loc(src)} → ${loc(sink)}` : (f.evidence?.sink ? loc(f.evidence.sink) : "");
  const conf = CONF_LABEL[f.confidence] || "疑似";
  const confOk = f.confidence === "CONFIRMED_DYNAMIC";
  return (
    <motion.button className="va-fr" onClick={onClick}
      initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}>
      <span className={`va-fr-dot ${s.dot}`} />
      <span className="va-fr-main">
        <span className="va-fr-title">{f.title}</span>
        {path && <span className="va-fr-path va-mono">{path}</span>}
      </span>
      {typeof f.severity?.score === "number" && <span className="va-fr-score va-mono">{f.severity.score.toFixed(1)}</span>}
      <span className={`va-fr-sev va-mono ${s.text}`}>{s.label}</span>
      <span className={`va-fr-act va-mono ${confOk ? "va-ok" : "va-dim"}`}>{conf}</span>
    </motion.button>
  );
}

// ---------- finding drawer ----------
function FindingDrawer({ f, onClose }: { f: Finding; onClose: () => void }) {
  const s = sevClass(f.severity?.level);
  const ev = f.evidence;
  const conf = CONF_LABEL[f.confidence] || "疑似";
  const poc = f.artifacts?.find((a) => a.kind === "poc_code");
  const reach = ev?.reachability || {};
  const sv = ev?.static_verdict || {};
  const dyn = ev?.dynamic_verification;
  const hops = buildTrace(ev);

  return (
    <>
      <motion.div className="va-mask" variants={maskV} initial="hidden" animate="show" exit="exit" onClick={onClose} />
      <motion.aside className="va-drawer" variants={drawerV} initial="hidden" animate="show" exit="exit">
        <div className="va-dr-head">
          <div className="va-dr-title-wrap">
            <h2 className="va-dr-title">{f.title}</h2>
            <div className="va-dr-sub va-mono">
              finding {f.id?.slice(0, 6)}
              {ev?.source?.file && <> · {ev.source.file} <span className="va-arrow">→</span> {ev?.sink?.file}</>}
            </div>
          </div>
          <button className="va-x" onClick={onClose}>✕</button>
        </div>

        <div className="va-dr-badge">
          <span className={`va-tag ${sevTagCls(s.key)}`}>
            <span className={`va-tag-dot ${s.dot}`} />
            {s.label} {typeof f.severity?.score === "number" ? f.severity.score.toFixed(1) : ""} · {conf}
          </span>
        </div>

        <div className="va-dr-body">
          {/* the trace */}
          <div className="va-sec">
            <div className="va-sec-h">证据链 <span className="va-mono va-dim">The Trace</span></div>
            <div className="va-trace-v">
              {hops.map((h, i) => (
                <div key={i} className={`va-tv-row ${h.kind}`}>
                  <span className="va-tv-rail">
                    <span className={`va-tv-node ${h.kind === "sink" ? "sink" : ""}`} />
                    {i < hops.length - 1 && <span className="va-tv-line" />}
                  </span>
                  <div className="va-tv-x">
                    <div className="va-tv-tag va-mono">{h.tag}</div>
                    <div className="va-tv-loc va-mono">{h.loc}</div>
                    {h.detail && <div className="va-tv-detail va-mono">{h.detail}</div>}
                  </div>
                </div>
              ))}
              {hops.length === 0 && <div className="va-dim va-mono">无污点路径数据</div>}
            </div>
          </div>

          {/* reachability + verification */}
          <div className="va-sec">
            <div className="va-sec-h">可达性与验证</div>
            <div className="va-verify va-mono">
              <span className={reach.reachable ? "va-ok" : "sv-medium"}>{reach.reachable ? "可达" : "待确认"}</span>
              {(reach.engine || reach.confidence != null) && (
                <span className="va-dim"> ({[reach.engine, reach.confidence != null ? `置信 ${reach.confidence}` : ""].filter(Boolean).join(", ")})</span>
              )}
              <span className="va-mid"> · </span>静态 <span>{sv.status || "—"}</span>
              <span className="va-mid"> · </span>
              动态沙箱 {dyn?.reproduced ? <span className="va-ok">复现</span> : dyn?.attempted ? <span className="sv-medium">未复现</span> : <span className="va-dim">跳过</span>}
            </div>
            {(sv.rationale || reach.note) && <div className="va-verify-note">{sv.rationale || reach.note}</div>}
          </div>

          {/* CVSS */}
          {f.cvss_explained && (
            <div className="va-sec">
              <div className="va-sec-h">CVSS v3.1 说明 <span className="va-mono va-dim">{f.cvss_explained.score} · {f.cvss_explained.level?.toUpperCase()}</span></div>
              <div className="va-cvss">
                {f.cvss_explained.metrics.map((m) => (
                  <div key={m.metric} className="va-cvss-i">
                    <span className="va-cvss-k">{m.label.split(" (")[0]}：</span>
                    <span className="va-cvss-v">{m.value_label.split(" (")[0]}</span>
                  </div>
                ))}
                <div className="va-cvss-i wide">
                  <span className="va-cvss-k">向量：</span>
                  <span className="va-cvss-v va-mono">{f.cvss_explained.vector}</span>
                </div>
              </div>
              <div className="va-cvss-note">据本实例的鉴权/暴露面/影响调整，非类别默认值</div>
            </div>
          )}

          {/* PoC */}
          {poc && (
            <div className="va-sec">
              <div className="va-sec-h">PoC</div>
              <pre className="va-code va-mono">{poc.content}</pre>
            </div>
          )}

          {/* remediation */}
          {f.remediation && (
            <div className="va-sec">
              <div className="va-sec-h">修复建议</div>
              <div className="va-remed">{f.remediation}</div>
            </div>
          )}
        </div>
      </motion.aside>
    </>
  );
}

// ---------- report sheet ----------
const FORMATS = [
  { key: "markdown", label: "Markdown", ext: "md" },
  { key: "json", label: "JSON", ext: "json" },
  { key: "sarif", label: "SARIF", ext: "sarif" },
];
function ReportSheet({ taskId, onClose }: { taskId: string; onClose: () => void }) {
  const [busy, setBusy] = useState("");
  const [err, setErr] = useState("");
  async function gen(fmt: string, ext: string) {
    setBusy(fmt); setErr("");
    try {
      const r = await api.report(taskId, fmt);
      const blob = new Blob([r.content], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = `veriaudit-${taskId.slice(0, 8)}.${ext}`; a.click();
      URL.revokeObjectURL(url);
    } catch (e: any) { setErr(String(e.message || e)); }
    finally { setBusy(""); }
  }
  return (
    <>
      <motion.div className="va-mask" variants={maskV} initial="hidden" animate="show" exit="exit" onClick={onClose} />
      <div className="va-modal">
        <motion.div className="va-card va-report" variants={popV} initial="hidden" animate="show" exit="exit">
          <div className="va-report-head">
            <div>
              <div className="va-label">报告导出</div>
              <div className="va-report-title">选择格式</div>
            </div>
            <button className="va-x" onClick={onClose}>✕</button>
          </div>
          {err && <div className="va-err va-mono">{err}</div>}
          <div className="va-report-list">
            {FORMATS.map((f) => (
              <div key={f.key} className="va-report-row">
                <span className="va-report-fmt">{f.label}</span>
                <button className="va-gen va-mono" disabled={!!busy} onClick={() => gen(f.key, f.ext)}>
                  {busy === f.key ? "生成中…" : "生成"}
                </button>
              </div>
            ))}
          </div>
        </motion.div>
      </div>
    </>
  );
}

// ---------- helpers ----------
function hhmm(ms: number) {
  const d = new Date(ms);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}
function loc(l: any) {
  return l ? `${l.file}:${l.line}` : "";
}
function sevTagCls(key: string) {
  return { critical: "t-crit", high: "t-high", medium: "t-med", low: "t-low", info: "t-mute" }[key] || "t-mute";
}
function buildTrace(ev: any): { kind: string; tag: string; loc: string; detail?: string }[] {
  if (!ev) return [];
  const out: { kind: string; tag: string; loc: string; detail?: string }[] = [];
  const path = ev.taint_path || [];
  if (ev.source) out.push({ kind: "source", tag: "SOURCE", loc: loc(ev.source), detail: ev.source.snippet });
  let hop = 0;
  path.forEach((h: any) => {
    // skip a hop that just repeats the source/sink location; number the shown hops sequentially
    const l = loc(h.location);
    if (l && l !== loc(ev.source) && l !== loc(ev.sink)) {
      hop += 1;
      out.push({ kind: "hop", tag: `HOP ${hop}`, loc: l,
        detail: [h.variable ? `[${h.variable}]` : "", h.transform, h.note].filter(Boolean).join(" ") });
    }
  });
  if (ev.sink) out.push({ kind: "sink", tag: "SINK", loc: loc(ev.sink), detail: ev.sink.snippet });
  return out;
}

const CSS = `
.va-con { height:100dvh; display:flex; flex-direction:column; overflow:hidden; }

.va-top { height:56px; flex:0 0 auto; display:flex; align-items:center; justify-content:space-between;
  padding:0 clamp(16px,3vw,32px); border-bottom:1px solid var(--hair); background:var(--panel); }
.va-top-l { display:flex; align-items:center; gap:14px; min-width:0; }
.va-top-r { display:flex; align-items:center; gap:8px; }
.va-back { background:none; border:none; cursor:pointer; letter-spacing:.1em; white-space:nowrap; }
.va-back:hover { color:var(--signal); }
.va-task-id { font-size:12px; color:var(--faint); }
.va-elapsed { font-size:13px; color:var(--muted); }
.va-spill { display:inline-flex; align-items:center; gap:6px; font-size:12px; padding:3px 10px; border:1px solid var(--hair); }
.va-spill.s-ok { color:var(--signal); border-color:rgba(11,138,99,.35); background:var(--signal-w); }
.va-spill.s-bad { color:var(--crit); border-color:rgba(184,50,39,.35); background:#FBEDEB; }
.va-spill.s-warn { color:var(--high); border-color:rgba(193,106,34,.35); }
.va-spill.s-mute { color:var(--faint); }

/* stepper */
.va-steps { position:relative; flex:0 0 auto; display:flex; justify-content:space-between;
  padding:20px clamp(24px,5vw,64px) 16px; background:var(--panel); border-bottom:1px solid var(--hair); }
.va-steps-line { position:absolute; left:clamp(40px,7vw,90px); right:clamp(40px,7vw,90px); top:26px; height:2px; background:var(--hair); }
.va-steps-fill { position:absolute; left:clamp(40px,7vw,90px); right:clamp(40px,7vw,90px); top:26px; height:2px; background:var(--signal); transform-origin:left center; }
.va-step { position:relative; display:flex; flex-direction:column; align-items:center; gap:9px; z-index:1; }
.va-step-node { width:12px; height:12px; border-radius:50%; background:#fff; border:2px solid var(--hair); }
.va-step-node.done { background:var(--signal); border-color:var(--signal); }
.va-step-node.active { border-color:var(--signal); box-shadow:0 0 0 4px var(--signal-w); }
.va-step-label { font-size:13px; color:var(--faint); }
.va-step-label.on { color:var(--ink); font-weight:500; }

/* degradation */
.va-degrade { flex:0 0 auto; display:flex; align-items:center; flex-wrap:wrap; gap:4px;
  background:#FAF4E6; border-bottom:1px solid #EADFC0; padding:9px clamp(24px,5vw,64px); font-size:12.5px; color:#8A6D1E; }
.va-degrade-k { font-weight:600; color:#8A6D1E; margin-right:6px; }
.va-degrade-note { color:#A08945; }

/* stats */
.va-stats { flex:0 0 auto; display:flex; background:var(--panel); border-bottom:1px solid var(--hair); }
.va-stat { flex:1; padding:18px clamp(16px,3vw,28px); border-right:1px solid var(--hair2); }
.va-stat.last { border-right:none; }
.va-stat-n { font-family:'Space Grotesk',sans-serif; font-weight:700; font-size:30px; line-height:1; color:var(--ink); }
/* tone overrides — higher specificity than the base .va-stat-n color so severities show their color */
.va-stat-n.sv-critical { color:var(--crit); }
.va-stat-n.sv-high { color:var(--high); }
.va-stat-n.sv-medium { color:var(--med); }
.va-stat-n.va-dim { color:var(--faint); }
.va-stat-l { font-size:12px; color:var(--muted); margin-top:6px; }

/* body */
.va-body { flex:1 1 auto; min-height:0; display:grid; grid-template-columns:1fr 1fr; gap:1px;
  background:var(--hair); }
.va-panel { display:flex; flex-direction:column; min-height:0; background:var(--paper); }
.va-panel-head { flex:0 0 auto; display:flex; align-items:baseline; gap:10px; padding:16px 22px 12px; }
.va-panel-t { font-weight:700; font-size:15px; }
.va-panel-tag { font-size:12px; color:var(--faint); display:inline-flex; align-items:center; gap:6px; }
.va-panel-body { flex:1 1 auto; min-height:0; overflow-y:auto; padding:4px 22px 22px; }
.va-flist-empty { color:var(--faint); font-size:13px; padding:32px 0; text-align:center; }

/* stream */
.va-stream-list { display:flex; flex-direction:column; gap:8px; }
.va-tl { display:flex; align-items:baseline; gap:8px; font-size:13px; }
.va-tl-t { color:var(--faint); font-size:12px; flex:none; width:38px; }
.va-tl-dot { width:7px; height:7px; border-radius:50%; flex:none; align-self:center; }
.va-tl-a { flex:none; font-weight:700; min-width:66px; }
.va-tl-arrow { color:#B7BEBB; flex:none; }
.va-tl-x { color:var(--ink); min-width:0; }
.va-tl-tool { color:var(--ink); background:var(--panel2); border:1px solid var(--hair);
  padding:1px 7px; border-radius:0; }
.va-tl-note { padding-left:52px; font-size:12.5px; color:var(--muted); line-height:1.55;
  border-left:2px solid var(--hair); margin-left:52px; padding-left:12px; }
.va-tl-note.scroll { max-height:190px; overflow-y:auto; }
.va-tl-note.warn { color:#8A6D1E; border-left-color:#EADFC0; }

/* model reasoning / output — bordered, scrollable, full content */
.va-reason { margin-left:52px; border:1px solid var(--hair); background:var(--panel); }
.va-reason-h { font-family:'JetBrains Mono',monospace; font-size:11px; font-weight:700;
  padding:6px 12px; border-bottom:1px solid var(--hair); border-left:3px solid; }
.va-reason-b { padding:9px 12px; font-size:12.5px; color:var(--muted); line-height:1.6;
  white-space:pre-wrap; max-height:220px; overflow-y:auto; }

/* adaptive budget / caps block */
.va-budget { margin-left:52px; border:1px solid rgba(46,124,196,.28); background:rgba(46,124,196,.05); }
.va-budget-h { font-family:'JetBrains Mono',monospace; font-size:12px; font-weight:700; color:#2E6FA8;
  padding:7px 12px; border-bottom:1px solid rgba(46,124,196,.2); }
.va-budget-r { padding:8px 12px 0; font-size:12px; color:var(--muted); line-height:1.55; }
.va-budget-chips { display:flex; flex-wrap:wrap; gap:7px; padding:9px 12px 11px; }
.va-budget-c { font-size:11.5px; color:#2E6FA8; border:1px solid rgba(46,124,196,.28); padding:2px 8px; }
.va-budget-ck { color:var(--muted); }

/* terminal audit-finished marker */
.va-done { display:flex; align-items:center; gap:9px; margin-top:8px; padding:11px 14px;
  font-size:13.5px; font-weight:700; border:1px solid; }
.va-done-mk { font-size:14px; }
.va-done-ok { color:var(--signal); border-color:rgba(11,138,99,.4); background:var(--signal-w); }
.va-done-bad { color:var(--crit); border-color:rgba(184,50,39,.4); background:#FBEDEB; }
.va-done-mute { color:var(--faint); border-color:var(--hair); background:var(--panel2); }

/* findings */
.va-fr { width:100%; display:flex; align-items:center; gap:12px; padding:14px 4px; text-align:left;
  background:none; border:none; border-bottom:1px solid var(--hair2); cursor:pointer; transition:background .12s; }
.va-fr:hover { background:var(--panel2); }
.va-fr-dot { width:9px; height:9px; border-radius:50%; flex:none; }
.va-fr-main { flex:1 1 auto; min-width:0; display:flex; flex-direction:column; gap:3px; }
.va-fr-title { font-size:14px; font-weight:500; color:var(--ink); }
.va-fr-path { font-size:12px; color:var(--faint); }
.va-fr-score { font-size:14px; color:var(--ink); flex:none; }
.va-fr-sev { font-size:13px; flex:none; width:40px; text-align:right; }
.va-fr-act { font-size:13px; flex:none; width:48px; text-align:right; }

.va-failbar { position:fixed; bottom:20px; left:50%; transform:translateX(-50%); z-index:30;
  background:#FBEDEB; border:1px solid var(--crit); color:var(--crit); padding:9px 16px; font-size:13px; }

/* drawer */
.va-mask { position:fixed; inset:0; background:rgba(20,24,27,.28); backdrop-filter:blur(2px); z-index:40; }
.va-drawer { position:fixed; top:0; right:0; bottom:0; width:100%; max-width:560px; z-index:50;
  background:var(--panel); border-left:1px solid var(--hair); display:flex; flex-direction:column; }
.va-dr-head { flex:0 0 auto; display:flex; align-items:flex-start; justify-content:space-between; gap:12px;
  padding:22px 24px 14px; border-bottom:1px solid var(--hair); }
.va-dr-title { font-family:'Space Grotesk',sans-serif; font-weight:700; font-size:22px; margin:0; }
.va-dr-sub { font-size:12px; color:var(--faint); margin-top:6px; }
.va-x { background:none; border:none; cursor:pointer; color:var(--faint); font-size:14px; flex:none; }
.va-x:hover { color:var(--ink); }
.va-dr-badge { flex:0 0 auto; padding:14px 24px; border-bottom:1px solid var(--hair); }
.va-dr-body { flex:1 1 auto; overflow-y:auto; padding:22px 24px 40px; }
.va-sec { margin-bottom:26px; }
.va-sec-h { font-weight:700; font-size:14px; margin-bottom:14px; display:flex; align-items:baseline; gap:8px; }

/* vertical trace */
.va-trace-v { display:flex; flex-direction:column; }
.va-tv-row { display:flex; gap:14px; }
.va-tv-rail { display:flex; flex-direction:column; align-items:center; width:14px; flex:none; }
.va-tv-node { width:12px; height:12px; border-radius:50%; margin-top:3px; background:#fff; border:2px solid var(--signal); flex:none; }
.va-tv-node.sink { background:var(--crit); border-color:var(--crit); }
.va-tv-line { width:2px; flex:1 1 auto; min-height:22px; background:var(--signal); margin:4px 0; opacity:.5; }
.va-tv-x { padding-bottom:18px; min-width:0; }
.va-tv-tag { font-size:10.5px; letter-spacing:.12em; color:var(--faint); }
.va-tv-loc { font-size:13px; color:var(--ink); margin-top:2px; }
.va-tv-detail { font-size:12px; color:var(--muted); margin-top:3px; }

.va-verify { font-size:13px; line-height:1.6; }
.va-verify-note { font-size:12.5px; color:var(--muted); margin-top:8px; line-height:1.55; }

.va-cvss { display:grid; grid-template-columns:1fr 1fr; gap:9px 24px; }
.va-cvss-i { font-size:13px; }
.va-cvss-i.wide { grid-column:1 / -1; }
.va-cvss-k { color:var(--muted); }
.va-cvss-v { color:var(--ink); }
.va-cvss-note { font-size:11.5px; color:var(--faint); margin-top:12px; }

.va-code { background:var(--panel2); border:1px solid var(--hair); padding:12px 14px; font-size:12px;
  color:var(--ink); overflow-x:auto; white-space:pre-wrap; line-height:1.55; }
.va-remed { font-size:13.5px; color:var(--muted); line-height:1.65; }

/* report sheet */
.va-modal { position:fixed; inset:0; display:grid; place-items:center; z-index:50; padding:24px; pointer-events:none; }
.va-report { width:100%; max-width:420px; pointer-events:auto; background:var(--panel); }
.va-report-head { display:flex; align-items:flex-start; justify-content:space-between; padding:22px 24px 16px; }
.va-report-title { font-family:'Space Grotesk',sans-serif; font-weight:700; font-size:22px; margin-top:6px; }
.va-report-list { border-top:1px solid var(--hair); }
.va-report-row { display:flex; align-items:center; justify-content:space-between; padding:16px 24px; border-bottom:1px solid var(--hair2); }
.va-report-row:last-child { border-bottom:none; }
.va-report-fmt { font-size:15px; font-weight:500; }
.va-gen { background:none; border:none; cursor:pointer; color:var(--signal); font-size:14px; font-weight:600; }
.va-gen:hover:not(:disabled) { text-decoration:underline; text-underline-offset:2px; }
.va-gen:disabled { color:var(--faint); cursor:default; }
.va-err { color:var(--crit); background:#FBEDEB; border:1px solid var(--crit); margin:0 24px 12px; padding:8px 12px; font-size:12px; }

@media (max-width:860px) {
  .va-body { grid-template-columns:1fr; grid-auto-rows:minmax(280px,auto); }
  .va-stats { overflow-x:auto; }
  .va-stat { min-width:88px; }
}
`;
