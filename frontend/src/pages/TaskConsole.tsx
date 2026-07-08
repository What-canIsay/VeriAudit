import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft, Activity, FileText, X, ChevronRight, Loader2, CheckCircle2, AlertTriangle,
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
  const [selected, setSelected] = useState<Finding | null>(null);
  const [reportOpen, setReportOpen] = useState(false);

  useEffect(() => {
    if (!id) return;
    setHistEvents([]);
    api.getTask(id).then((t) => {
      setTask(t);
      const done = ["succeeded", "failed"].includes(t.status);
      setLive(!done);
      if (done) {
        api.findings(id).then(setFindings).catch(() => {});
        api.timeline(id).then((items) => setHistEvents(timelineToEvents(items))).catch(() => {});
      }
    });
  }, [id]);

  useEffect(() => {
    if (!id || live === false) return;
    if (findingIds.length > 0 || finished) api.findings(id).then(setFindings).catch(() => {});
  }, [id, live, findingIds.length, finished]);

  async function openFinding(fid: string) {
    const full = await api.finding(fid);
    setSelected(full);
  }

  // finished task (revisit): drive from persisted DB state; live task: from SSE.
  const events = live === false ? histEvents : liveEvents;
  const liveStatus = live === false ? (task?.status || "succeeded") : (status || task?.status || "running");
  const curPhase = live === false ? "report" : (phase || task?.phase || "plan");
  const counts = live === false ? (task?.counts || {}) : (Object.keys(sseCounts).length ? sseCounts : task?.counts || {});
  const bys = counts.by_severity || {};

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
        <button className="btn-outline" onClick={() => setReportOpen(true)} disabled={!finished && liveStatus !== "succeeded"}>
          <FileText className="w-4 h-4" /> 审计报告
        </button>
      </header>

      {/* phase stepper */}
      <div className="px-6 py-3 border-b border-border flex items-center gap-1 shrink-0 overflow-x-auto">
        {PHASES.map((p, i) => {
          const done = PHASES.indexOf(curPhase) > i || liveStatus === "succeeded";
          const active = curPhase === p && liveStatus !== "succeeded";
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
