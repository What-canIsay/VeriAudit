import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft, Activity, FileText, X, ChevronRight, Loader2, CheckCircle2, AlertTriangle,
  Pause, Play, Square, Clock,
} from "lucide-react";
import { api } from "../api";
import type { Finding, Task } from "../types";
import { useTaskEvents, timelineToEvents, type LiveEvent } from "../lib/useTaskEvents";
import Timeline from "../components/Timeline";
import EvidenceChain from "../components/EvidenceChain";
import { StatCard, SeverityBar } from "../components/StatCard";
import { SeverityBadge, ConfidenceBadge } from "../components/Badge";
import ReportModal from "../components/ReportModal";

const PHASES = ["assess", "plan", "recon", "hunt", "trace", "provision", "verify", "report"];
const PHASE_LABEL: Record<string, string> = {
  assess: "评估", plan: "规划", recon: "侦察", hunt: "发现", trace: "追踪",
  provision: "搭建", verify: "验证", report: "报告",
};

export default function TaskConsole() {
  const { id } = useParams();
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

  // Pull the CURRENT findings straight from the DB (not just via live events). This is what
  // surfaces findings confirmed BEFORE the console connected — those `finding.confirmed`
  // events may have been evicted from the bounded SSE history, so we can't rely on them alone.
  const inFlight = useRef(false);
  const refreshFindings = useCallback(() => {
    if (!id || inFlight.current) return;   // skip if a fetch is still pending (avoid pileup)
    inFlight.current = true;
    Promise.allSettled([
      api.findings(id).then(setFindings),
      api.findings(id, "REJECTED").then((r) => setRejectedCount(r.length)),
    ]).finally(() => {
      inFlight.current = false;
    });
  }, [id]);

  useEffect(() => {
    if (!id) return;
    setHistEvents([]);
    api.getTask(id).then((t) => {
      setTask(t);
      const done = ["succeeded", "failed", "cancelled"].includes(t.status);
      setLive(!done);
      refreshFindings();   // fetch existing findings for BOTH running and finished tasks
      if (done) {
        api.timeline(id).then((items) => setHistEvents(timelineToEvents(items))).catch(() => {});
      }
    });
  }, [id, refreshFindings]);

  // event-driven refresh (fast path when a new finding is confirmed live)
  useEffect(() => {
    if (!id || live === false) return;
    if (findingIds.length > 0 || finished) refreshFindings();
  }, [id, live, findingIds.length, finished, refreshFindings]);

  // poll while the task is live, so findings appear even if their confirmation event was
  // missed (SSE history is bounded / reconnects lose old events).
  useEffect(() => {
    if (!id || live === false || finished) return;
    const t = setInterval(refreshFindings, 6000);
    return () => clearInterval(t);
  }, [id, live, finished, refreshFindings]);

  // when a live task finishes, refetch it once so finished_at freezes the elapsed timer.
  useEffect(() => {
    if (id && finished) api.getTask(id).then(setTask).catch(() => {});
  }, [id, finished]);

  // elapsed timer: ticks every second from started_at, freezes when the task ends.
  // parseTs treats the timestamps as UTC (the backend serializes naive UTC WITHOUT an
  // offset; without this the browser adds its local offset → the timer starts at e.g. 8:00:00).
  const startedMs = parseTs(task?.started_at);
  const finishedMs = parseTs(task?.finished_at);
  // terminal = the task has ended (from the SSE finished flag OR a terminal status), so the
  // timer freezes even if the post-finish finished_at refetch hasn't landed / was blocked.
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
      setTask(await fn(id));   // optimistic; SSE task.status will confirm
    } catch {
      /* ignore — SSE reflects the true state */
    } finally {
      setBusy(false);
    }
  }

  async function openFinding(fid: string) {
    const full = await api.finding(fid);
    setSelected(full);
  }

  // finished task (revisit): drive from persisted DB state; live task: from SSE.
  const events = live === false ? histEvents : liveEvents;
  const liveStatus = live === false ? (task?.status || "succeeded") : (status || task?.status || "running");
  const curPhase = live === false ? "report" : (phase || task?.phase || "plan");

  // While the task is RUNNING its DB counts aren't populated yet (reporter writes them at the
  // end), so derive live counts from the fetched findings + rejected count. Once finished, use
  // the authoritative counts (SSE task.finished / refetched task.counts).
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
  const counts = isLiveRunning
    ? derivedCounts
    : (live === false ? (task?.counts || {}) : (Object.keys(sseCounts).length ? sseCounts : task?.counts || {}));
  const bys = counts.by_severity || {};

  // capability degradations (fallbacks) — dedup, so the user is never misled into
  // thinking the system is running at max capability when it isn't.
  const notices = (() => {
    const seen = new Set<string>(); const out: any[] = [];
    for (const e of events) {
      if (e.event !== "degradation.notice") continue;
      const k = (e.data?.mechanism || "") + "|" + (e.data?.detail || "");
      if (seen.has(k)) continue; seen.add(k); out.push(e.data);
    }
    return out;
  })();

  return (
    <div className="flex flex-col h-dvh">
      {/* header */}
      <header className="h-16 border-b border-border flex items-center justify-between px-6 shrink-0">
        <div className="flex items-center gap-3 min-w-0">
          <Link to="/" className="btn-ghost px-2"><ArrowLeft className="w-4 h-4" /></Link>
          <div className="min-w-0">
            <h1 className="text-base font-semibold flex items-center gap-2">
              审计控制台
              <StatusPill status={liveStatus} />
            </h1>
            <div className="text-xs text-faint font-mono truncate">task {id}</div>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {/* elapsed timer */}
          {startedMs && (
            <span className="chip text-muted border-border font-mono tabular-nums" title="审计已运行时长">
              <Clock className="w-3.5 h-3.5" /> {fmtElapsed(elapsedMs)}
            </span>
          )}
          {/* run controls */}
          {liveStatus === "running" && (
            <>
              <button className="btn-outline" disabled={busy} onClick={() => doControl("pause")}>
                <Pause className="w-4 h-4" /> 暂停
              </button>
              <button className="btn-outline text-critical border-critical/40 hover:bg-critical/10"
                disabled={busy} onClick={() => doControl("cancel")}>
                <Square className="w-4 h-4" /> 停止
              </button>
            </>
          )}
          {liveStatus === "paused" && (
            <>
              <button className="btn-primary" disabled={busy} onClick={() => doControl("resume")}>
                <Play className="w-4 h-4" /> 继续
              </button>
              <button className="btn-outline text-critical border-critical/40 hover:bg-critical/10"
                disabled={busy} onClick={() => doControl("cancel")}>
                <Square className="w-4 h-4" /> 停止
              </button>
            </>
          )}
          {liveStatus === "cancelling" && (
            <span className="chip text-amber-300 border-amber-500/40 bg-amber-500/10">
              <Loader2 className="w-3.5 h-3.5 animate-spin" /> 停止中…
            </span>
          )}
          <button className="btn-outline" onClick={() => setReportOpen(true)} disabled={!finished && liveStatus !== "succeeded"}>
            <FileText className="w-4 h-4" /> 审计报告
          </button>
        </div>
      </header>

      {/* phase stepper */}
      <div className="px-6 py-3 border-b border-border flex items-center gap-1 shrink-0 overflow-x-auto">
        {PHASES.map((p, i) => {
          const done = PHASES.indexOf(curPhase) > i || liveStatus === "succeeded";
          const active = curPhase === p && !["succeeded", "failed", "cancelled"].includes(liveStatus);
          return (
            <div key={p} className="flex items-center gap-1 shrink-0">
              <span className={`chip ${done ? "text-accent border-accent/40 bg-accent/10" : active ? "text-fg border-accent/60 bg-surface-3" : "text-faint border-border"}`}>
                {active && <span className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse-dot" />}
                {done && <CheckCircle2 className="w-3 h-3" />}
                {PHASE_LABEL[p]}
              </span>
              {i < PHASES.length - 1 && <ChevronRight className="w-3.5 h-3.5 text-faint" />}
            </div>
          );
        })}
      </div>

      {/* capability degradation banner */}
      {notices.length > 0 && (
        <div className="px-6 pt-3 shrink-0">
          <div className="rounded-lg border border-amber-500/50 bg-amber-500/10 px-4 py-2.5">
            <div className="flex items-center gap-2 mb-1.5">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
              <span className="text-sm font-semibold text-amber-300">能力降级提示 · 本次审计未在最大能力下运行</span>
              <span className="chip text-amber-300/80 border-amber-500/40 ml-1">{notices.length}</span>
            </div>
            <ul className="space-y-1 pl-6">
              {notices.map((n, i) => (
                <li key={i} className="text-xs flex items-start gap-1.5">
                  <span className={`mt-1 w-1.5 h-1.5 rounded-full shrink-0 ${n.severity === "error" ? "bg-critical" : "bg-amber-400"}`} />
                  <span className={n.severity === "error" ? "text-critical" : "text-amber-200/90"}>
                    <span className="font-medium">{n.mechanism}</span>：{n.detail}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {/* stat cards */}
      <div className="px-6 py-4 grid grid-cols-2 lg:grid-cols-5 gap-3 shrink-0">
        <StatCard label="确认漏洞" value={counts.total_findings ?? findings.length} tone="fg"
          sub={`动态复现 ${counts.confirmed_dynamic ?? 0}`} />
        <StatCard label="严重" value={bys.critical ?? 0} tone="critical" />
        <StatCard label="高危" value={bys.high ?? 0} tone="high" />
        <StatCard label="疑似待复核" value={counts.suspected ?? 0} tone="medium" />
        <StatCard label="已排除" value={counts.rejected ?? 0} tone="muted" />
      </div>
      <div className="px-6 pb-3 shrink-0">
        <SeverityBar by={bys} />
      </div>

      {/* main split */}
      <div className="flex-1 min-h-0 grid lg:grid-cols-2 gap-4 px-6 pb-6">
        {/* timeline */}
        <section className="card flex flex-col min-h-0">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-border shrink-0">
            <Activity className="w-4 h-4 text-accent" />
            <span className="font-medium text-sm">智能体执行时间线</span>
            {!finished && liveStatus === "running" && (
              <span className="ml-auto flex items-center gap-1.5 text-xs text-accent">
                <Loader2 className="w-3.5 h-3.5 animate-spin" /> 实时
              </span>
            )}
          </div>
          <div className="flex-1 min-h-0 overflow-y-auto p-4">
            <Timeline events={events} />
          </div>
        </section>

        {/* findings */}
        <section className="card flex flex-col min-h-0">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-border shrink-0">
            <span className="font-medium text-sm">漏洞列表</span>
            <span className="chip text-muted border-border ml-1">{findings.length}</span>
          </div>
          <div className="flex-1 min-h-0 overflow-y-auto divide-y divide-border/60">
            {findings.length === 0 && (
              <div className="text-sm text-faint py-10 text-center">
                {liveStatus === "running" ? "验证中，确认的漏洞将实时出现…" : "暂无确认漏洞"}
              </div>
            )}
            {findings.map((f) => (
              <button key={f.id} onClick={() => openFinding(f.id)}
                className="w-full text-left px-4 py-3 hover:bg-surface-3/50 transition-colors flex flex-col gap-1.5">
                <div className="flex items-center gap-2">
                  <SeverityBadge level={f.severity?.level} score={f.severity?.score} />
                  <ConfidenceBadge value={f.confidence} />
                  <ChevronRight className="w-4 h-4 text-faint ml-auto" />
                </div>
                <div className="font-mono text-xs text-fg truncate">{f.title}</div>
              </button>
            ))}
          </div>
        </section>
      </div>

      {/* finding detail drawer */}
      {selected && (
        <>
          <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-40 animate-fade-in" onClick={() => setSelected(null)} />
          <aside className="fixed right-0 top-0 bottom-0 w-full max-w-xl bg-surface border-l border-border z-50 flex flex-col animate-fade-in">
            <div className="flex items-center justify-between px-5 py-4 border-b border-border shrink-0">
              <span className="font-medium text-sm">漏洞证据链</span>
              <button className="btn-ghost px-2" onClick={() => setSelected(null)}><X className="w-4 h-4" /></button>
            </div>
            <div className="flex-1 overflow-y-auto p-5">
              <EvidenceChain f={selected} />
            </div>
          </aside>
        </>
      )}

      {reportOpen && id && <ReportModal taskId={id} onClose={() => setReportOpen(false)} />}

      {liveStatus === "failed" && (
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 chip text-critical border-critical/40 bg-critical/10 z-30">
          <AlertTriangle className="w-4 h-4" /> 审计失败：{task?.error}
        </div>
      )}
    </div>
  );
}

function StatusPill({ status }: { status: string }) {
  const map: Record<string, { t: string; c: string }> = {
    running: { t: "进行中", c: "text-accent border-accent/40 bg-accent/10" },
    paused: { t: "已暂停", c: "text-amber-300 border-amber-500/40 bg-amber-500/10" },
    cancelling: { t: "停止中", c: "text-amber-300 border-amber-500/40 bg-amber-500/10" },
    cancelled: { t: "已停止", c: "text-muted border-border" },
    succeeded: { t: "已完成", c: "text-accent border-accent/40 bg-accent/10" },
    failed: { t: "失败", c: "text-critical border-critical/40 bg-critical/10" },
    queued: { t: "排队中", c: "text-muted border-border" },
  };
  const m = map[status] || map.queued;
  return (
    <span className={`chip ${m.c}`}>
      {status === "running" && <span className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse-dot" />}
      {m.t}
    </span>
  );
}

function fmtElapsed(ms: number | null): string {
  if (ms == null || ms < 0) return "00:00";
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  const pad = (n: number) => String(n).padStart(2, "0");
  return h > 0 ? `${h}:${pad(m)}:${pad(sec)}` : `${pad(m)}:${pad(sec)}`;
}

// Parse a backend timestamp. The backend serializes naive UTC WITHOUT a timezone offset;
// treat an offset-less string as UTC (not the browser's local zone) to avoid an 8h skew.
function parseTs(s?: string | null): number | null {
  if (!s) return null;
  const iso = /[zZ]|[+-]\d\d:?\d\d$/.test(s) ? s : s + "Z";
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? null : ms;
}
