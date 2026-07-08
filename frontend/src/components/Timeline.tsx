import { useEffect, useRef } from "react";
import {
  Brain, Wrench, Radar, Bug, GitBranch, ShieldCheck, FileText,
  Cpu, CheckCircle2, XCircle, FlaskConical, Circle, Container, Gauge, AlertTriangle,
} from "lucide-react";
import type { LiveEvent } from "../lib/useTaskEvents";
import { agentMeta } from "../lib/format";

const AGENT_ICON: Record<string, any> = {
  profiler: Gauge, planner: Cpu, recon: Radar, hunter: Bug, tracer: GitBranch,
  provisioner: Container, validator: ShieldCheck, reporter: FileText,
};

export default function Timeline({ events }: { events: LiveEvent[] }) {
  const endRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [events.length]);

  const rows = events.map((e) => renderRow(e)).filter(Boolean);

  return (
    <div className="flex flex-col gap-1.5">
      {rows.length === 0 && (
        <div className="text-sm text-faint py-8 text-center">等待智能体启动…</div>
      )}
      {rows}
      <div ref={endRef} />
    </div>
  );
}

function renderRow(e: LiveEvent) {
  const d = e.data || {};
  switch (e.event) {
    case "agent.started": {
      const m = agentMeta(d.agent);
      const Icon = AGENT_ICON[d.agent] || Circle;
      return (
        <Row key={e.seq} tone="agent">
          <span className={`shrink-0 ${m.color}`}>
            <Icon className="w-4 h-4" />
          </span>
          <span className={`font-medium ${m.color}`}>{m.label}</span>
          <span className="text-faint">开始工作</span>
          <span className="text-faint font-mono text-xs ml-auto">{d.node}</span>
        </Row>
      );
    }
    case "agent.thinking":
      return (
        <Row key={e.seq} tone="think">
          <Brain className="w-3.5 h-3.5 text-faint shrink-0 mt-0.5" />
          <span className="text-muted italic">{d.text}</span>
        </Row>
      );
    case "agent.reasoning": {
      const m = agentMeta(d.agent);
      return (
        <div key={e.seq} className="pl-6 animate-fade-in">
          <div className="rounded-lg border border-border bg-surface-2/60 overflow-hidden">
            <div className="flex items-center gap-1.5 px-3 py-1.5 border-b border-border/60">
              <Brain className={`w-3.5 h-3.5 ${m.color}`} />
              <span className={`text-xs font-medium ${m.color}`}>{m.label} · 模型思考</span>
            </div>
            <div className="px-3 py-2 text-xs text-muted whitespace-pre-wrap max-h-52 overflow-y-auto leading-relaxed font-sans">
              {d.text}
            </div>
          </div>
        </div>
      );
    }
    case "agent.llm_output":
      return (
        <div key={e.seq} className="pl-6 animate-fade-in">
          <div className="text-xs text-fg/90 bg-surface-3/40 border-l-2 border-accent/50 rounded-r px-3 py-1.5 whitespace-pre-wrap max-h-40 overflow-y-auto">
            {d.text}
          </div>
        </div>
      );
    case "tool.invoked":
      return (
        <Row key={e.seq} tone="tool">
          <Wrench className="w-3.5 h-3.5 text-sky-400 shrink-0" />
          <span className="font-mono text-xs text-sky-300">{d.tool}</span>
          {d.args_brief && Object.keys(d.args_brief).length > 0 && (
            <span className="font-mono text-[11px] text-faint truncate">
              {Object.entries(d.args_brief).map(([k, v]) => `${k}=${v}`).join(" ")}
            </span>
          )}
        </Row>
      );
    case "assess.ready": {
      const p = d.profile || {};
      const b = d.budget || {};
      return (
        <div key={e.seq} className="pl-6 animate-fade-in">
          <div className="rounded-lg border border-teal-500/30 bg-teal-500/5 overflow-hidden">
            <div className="flex items-center gap-1.5 px-3 py-1.5 border-b border-teal-500/20">
              <Gauge className="w-3.5 h-3.5 text-teal-400" />
              <span className="text-xs font-medium text-teal-300">规模评估 · 档位 {p.tier}</span>
            </div>
            <div className="px-3 py-2 text-[11px] text-muted leading-relaxed">
              <div className="mb-1">{p.rationale}</div>
              <div className="flex flex-wrap gap-1.5 font-mono">
                {[
                  ["挖掘步数", b.llm_hunt_steps],
                  ["候选上限", b.max_candidates],
                  ["验证上限", b.max_verify],
                  ["搭建步数", b.provisioner_max_steps],
                  ["搭建时长", b.provisioner_timeout_sec && `${b.provisioner_timeout_sec}s`],
                  ["任务时长", b.task_timeout_sec && `${b.task_timeout_sec}s`],
                ].filter(([, v]) => v != null && v !== false).map(([k, v]) => (
                  <span key={String(k)} className="chip text-teal-300/80 border-teal-500/30">{k} {v}</span>
                ))}
              </div>
            </div>
          </div>
        </div>
      );
    }
    case "candidate.recorded":
      return (
        <Row key={e.seq} tone="tool">
          <Bug className="w-3.5 h-3.5 text-amber-400 shrink-0" />
          <span className="text-amber-300/90 text-xs">候选</span>
          <span className="font-mono text-xs truncate">{d.vuln_type}</span>
          <span className="font-mono text-[11px] text-faint truncate">
            {d.location?.file}:{d.location?.line}
          </span>
        </Row>
      );
    case "sandbox.poc_attempt":
      return (
        <Row key={e.seq} tone="tool">
          <FlaskConical className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
          <span className="text-xs">沙箱 PoC</span>
          <span className="font-mono text-xs truncate">{d.vuln_type}</span>
          <span className={`text-xs ml-auto ${d.reproduced ? "text-accent" : "text-faint"}`}>
            {d.reproduced ? "✓ 已复现" : d.attempted ? "未复现" : "跳过"}
          </span>
        </Row>
      );
    case "provision.ready":
      return (
        <Row key={e.seq} tone="ok">
          <Container className="w-4 h-4 text-orange-400 shrink-0" />
          <span className="text-orange-300">环境就绪</span>
          <span className="text-xs text-faint">端口 {d.port} · {d.by === "llm" ? "模型搭建" : "确定性搭建"}</span>
        </Row>
      );
    case "preheat.ready":
      return (
        <Row key={e.seq} tone="ok">
          <Container className="w-4 h-4 text-orange-400 shrink-0" />
          <span className="text-orange-300 text-xs">核验预热就绪</span>
          {Array.isArray(d.sessions) && d.sessions.length > 0 && (
            <span className="text-[11px] text-faint font-mono">会话: {d.sessions.join(", ")}</span>
          )}
        </Row>
      );
    case "degradation.notice":
      return (
        <Row key={e.seq} tone="muted">
          <AlertTriangle className={`w-3.5 h-3.5 shrink-0 ${d.severity === "error" ? "text-critical" : "text-amber-400"}`} />
          <span className={`text-xs ${d.severity === "error" ? "text-critical" : "text-amber-300"}`}>
            能力降级 · {d.mechanism}
          </span>
          <span className="text-[11px] text-faint truncate">{d.detail}</span>
        </Row>
      );
    case "provision.failed":
      return (
        <Row key={e.seq} tone="muted">
          <XCircle className="w-3.5 h-3.5 text-faint shrink-0" />
          <span className="text-faint text-xs">环境未搭建成功（回落逐候选复现）：{d.reason}</span>
        </Row>
      );
    case "finding.confirmed":
      return (
        <Row key={e.seq} tone="ok">
          <CheckCircle2 className="w-4 h-4 text-accent shrink-0" />
          <span className="text-accent">确认漏洞</span>
          <span className="font-mono text-xs truncate">{d.title || d.vuln_type}</span>
          <span className="text-[11px] text-faint ml-auto">{d.confidence}</span>
        </Row>
      );
    case "finding.rejected":
      return (
        <Row key={e.seq} tone="muted">
          <XCircle className="w-3.5 h-3.5 text-faint shrink-0" />
          <span className="text-faint text-xs">已排除</span>
          <span className="font-mono text-xs text-faint truncate">{d.vuln_type}</span>
        </Row>
      );
    case "task.status":
      if (d.status === "running")
        return (
          <Row key={e.seq} tone="phase">
            <span className="w-2 h-2 rounded-full bg-accent animate-pulse-dot shrink-0" />
            <span className="text-muted text-xs">阶段 → {d.phase}</span>
          </Row>
        );
      return null;
    default:
      return null;
  }
}

function Row({ children, tone }: { children: React.ReactNode; tone: string }) {
  const pad = tone === "think" || tone === "tool" ? "pl-6" : "";
  return (
    <div className={`flex items-center gap-2 text-sm animate-fade-in ${pad}`}>
      {children}
    </div>
  );
}
