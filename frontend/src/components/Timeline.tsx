import { useEffect, useRef } from "react";
import {
  Brain, Wrench, Radar, Bug, GitBranch, ShieldCheck, FileText,
  Cpu, CheckCircle2, XCircle, FlaskConical, Circle,
} from "lucide-react";
import type { LiveEvent } from "../lib/useTaskEvents";
import { agentMeta } from "../lib/format";

const AGENT_ICON: Record<string, any> = {
  planner: Cpu, recon: Radar, hunter: Bug, tracer: GitBranch,
  validator: ShieldCheck, reporter: FileText,
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
