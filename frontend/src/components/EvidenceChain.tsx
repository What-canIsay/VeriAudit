import {
  MapPin, ArrowDown, Radar, Crosshair, ShieldCheck, FlaskConical,
  Wrench, Lightbulb, Terminal,
} from "lucide-react";
import type { Finding } from "../types";
import { SeverityBadge, ConfidenceBadge } from "./Badge";

export default function EvidenceChain({ f }: { f: Finding }) {
  const ev = f.evidence;
  const poc = f.artifacts?.find((a) => a.kind === "poc_code");
  const log = f.artifacts?.find((a) => a.kind === "sandbox_log");
  const dyn = ev?.dynamic_verification;

  return (
    <div className="space-y-5">
      <div>
        <div className="flex flex-wrap items-center gap-2 mb-1.5">
          <SeverityBadge level={f.severity?.level} score={f.severity?.score} />
          <ConfidenceBadge value={f.confidence} title />
        </div>
        <h3 className="font-mono text-sm text-fg break-all">{f.title}</h3>
        <div className="text-xs text-faint font-mono mt-1">{f.vuln_type} · {f.cvss_vector}</div>
      </div>

      {/* ① 位置 */}
      <Section n="①" title="位置">
        <div className="grid gap-1.5">
          {ev?.entry_point && <LocRow icon={<MapPin className="w-3.5 h-3.5" />} tag="入口" loc={ev.entry_point} tone="text-violet-400" />}
          {ev?.source && <LocRow icon={<Radar className="w-3.5 h-3.5" />} tag="source" loc={ev.source} tone="text-sky-400" />}
          {ev?.sink && <LocRow icon={<Crosshair className="w-3.5 h-3.5" />} tag="sink" loc={ev.sink} tone="text-critical" />}
        </div>
      </Section>

      {/* ② 污点路径 */}
      <Section n="②" title="调用 / 污点路径">
        <div className="relative">
          {(ev?.taint_path || []).map((h, i, arr) => (
            <div key={i} className="relative">
              <div className="flex items-start gap-3">
                <div className="flex flex-col items-center pt-1">
                  <span className={`w-2.5 h-2.5 rounded-full border ${i === 0 ? "bg-sky-400 border-sky-400" : i === arr.length - 1 ? "bg-critical border-critical" : "bg-surface-3 border-border-strong"}`} />
                  {i < arr.length - 1 && <span className="w-px flex-1 min-h-[26px] bg-border-strong my-0.5" />}
                </div>
                <div className="pb-3 min-w-0 flex-1">
                  <div className="font-mono text-xs text-muted">
                    {h.location?.file}:{h.location?.line}
                    {h.variable && <span className="text-amber-300"> [{h.variable}]</span>}
                  </div>
                  <div className="text-xs text-faint">{h.transform} {h.note && `· ${h.note}`}</div>
                </div>
              </div>
            </div>
          ))}
          {(!ev?.taint_path || ev.taint_path.length === 0) && (
            <div className="text-xs text-faint">无污点路径数据。</div>
          )}
        </div>
      </Section>

      {/* ③ 可达性 */}
      <Section n="③" title="可达性">
        <div className="flex items-center gap-2 text-sm">
          <span className={`chip ${ev?.reachability?.reachable ? "text-accent border-accent/40 bg-accent/10" : "text-medium border-medium/40 bg-medium/10"}`}>
            {ev?.reachability?.reachable ? "可达" : "待确认"}
          </span>
          <span className="text-xs text-faint">置信 {ev?.reachability?.confidence ?? "-"}</span>
        </div>
        {ev?.reachability?.note && <div className="text-xs text-muted mt-1.5">{ev.reachability.note}</div>}
      </Section>

      {/* ④ 验证 */}
      <Section n="④" title="验证">
        <div className="space-y-2.5">
          <div className="flex items-start gap-2">
            <ShieldCheck className="w-4 h-4 text-low shrink-0 mt-0.5" />
            <div className="text-sm">
              <span className="text-low">静态判定</span>
              <span className="font-mono text-xs text-faint ml-2">{ev?.static_verdict?.status}</span>
              <div className="text-xs text-muted mt-0.5">{ev?.static_verdict?.rationale}</div>
            </div>
          </div>
          {dyn && dyn.attempted && (
            <div className="flex items-start gap-2">
              <FlaskConical className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
              <div className="text-sm">
                <span className={dyn.reproduced ? "text-accent" : "text-muted"}>
                  动态沙箱 {dyn.reproduced ? "✓ 已复现" : "未复现"}
                </span>
                <div className="text-xs text-muted mt-0.5">{dyn.observation || dyn.reason}</div>
                {log && (
                  <pre className="mt-2 text-[11px] font-mono bg-black/40 border border-border rounded-lg p-2.5 overflow-x-auto text-emerald-300/90">
{log.content}
                  </pre>
                )}
              </div>
            </div>
          )}
          {dyn && !dyn.attempted && dyn.reason && (
            <div className="text-xs text-faint pl-6">动态验证跳过：{dyn.reason}</div>
          )}
        </div>
      </Section>

      {/* PoC */}
      {poc && (
        <Section n="" title="PoC / 利用代码" icon={<Terminal className="w-3.5 h-3.5" />}>
          <pre className="text-xs font-mono bg-black/40 border border-border rounded-lg p-3 overflow-x-auto text-fg whitespace-pre-wrap">
{poc.content}
          </pre>
        </Section>
      )}

      {/* 修复建议 */}
      {f.remediation && (
        <Section n="" title="修复建议" icon={<Lightbulb className="w-3.5 h-3.5 text-medium" />}>
          <div className="text-sm text-muted leading-relaxed">{f.remediation}</div>
        </Section>
      )}
    </div>
  );
}

function Section({ n, title, icon, children }: any) {
  return (
    <div>
      <div className="flex items-center gap-2 mb-2">
        {icon || (n && <span className="font-mono text-accent text-sm">{n}</span>)}
        <span className="label">{title}</span>
      </div>
      <div className="pl-1">{children}</div>
    </div>
  );
}

function LocRow({ icon, tag, loc, tone }: any) {
  return (
    <div className="flex items-center gap-2 text-sm">
      <span className={tone}>{icon}</span>
      <span className={`font-mono text-[11px] ${tone}`}>{tag}</span>
      <span className="font-mono text-xs text-muted truncate">
        {loc.file}:{loc.line}
        {loc.function && <span className="text-faint"> ({loc.function})</span>}
      </span>
    </div>
  );
}
