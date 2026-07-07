// Severity + confidence semantic maps (docs/06, docs/07 visual spec)

export const SEVERITY: Record<
  string,
  { label: string; text: string; bg: string; border: string; dot: string }
> = {
  critical: { label: "严重", text: "text-critical", bg: "bg-critical/10", border: "border-critical/40", dot: "bg-critical" },
  high: { label: "高危", text: "text-high", bg: "bg-high/10", border: "border-high/40", dot: "bg-high" },
  medium: { label: "中危", text: "text-medium", bg: "bg-medium/10", border: "border-medium/40", dot: "bg-medium" },
  low: { label: "低危", text: "text-low", bg: "bg-low/10", border: "border-low/40", dot: "bg-low" },
  info: { label: "信息", text: "text-info", bg: "bg-info/10", border: "border-info/40", dot: "bg-info" },
};

export function sev(level?: string) {
  return SEVERITY[level || "info"] || SEVERITY.info;
}

export const CONFIDENCE: Record<
  string,
  { label: string; text: string; border: string; style: "solid" | "outline" | "dashed"; hint: string }
> = {
  CONFIRMED_DYNAMIC: { label: "已动态复现", text: "text-accent", border: "border-accent", style: "solid", hint: "沙箱中 PoC 成功触发，最高置信度" },
  CONFIRMED_STATIC: { label: "数据流已确证", text: "text-low", border: "border-low", style: "outline", hint: "污点路径完整、可达、无有效净化" },
  SUSPECTED: { label: "疑似·待复核", text: "text-medium", border: "border-medium", style: "dashed", hint: "证据链存在缺口，建议人工复核" },
  REJECTED: { label: "已排除", text: "text-faint", border: "border-faint", style: "outline", hint: "不可达 / 被证伪 / 有效净化" },
};

export function conf(c?: string) {
  return CONFIDENCE[c || "SUSPECTED"] || CONFIDENCE.SUSPECTED;
}

export const AGENT_META: Record<string, { label: string; color: string }> = {
  planner: { label: "编排官", color: "text-violet-400" },
  recon: { label: "侦察员", color: "text-sky-400" },
  hunter: { label: "漏洞猎手", color: "text-amber-400" },
  tracer: { label: "污点追踪员", color: "text-cyan-400" },
  validator: { label: "验证官", color: "text-accent" },
  reporter: { label: "报告官", color: "text-rose-400" },
  system: { label: "系统", color: "text-muted" },
};

export function agentMeta(a?: string) {
  return AGENT_META[a || "system"] || AGENT_META.system;
}

export function shortTime(ts?: string | null) {
  if (!ts) return "";
  try {
    return new Date(ts).toLocaleTimeString("zh-CN", { hour12: false });
  } catch {
    return "";
  }
}
