import { conf, sev } from "../lib/format";

export function SeverityBadge({ level, score }: { level?: string; score?: number }) {
  const s = sev(level);
  return (
    <span className={`chip ${s.bg} ${s.text} ${s.border}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${s.dot}`} />
      {s.label}
      {typeof score === "number" && <span className="text-faint font-mono">{score.toFixed(1)}</span>}
    </span>
  );
}

export function ConfidenceBadge({ value, title }: { value?: string; title?: boolean }) {
  const c = conf(value);
  const border =
    c.style === "solid"
      ? `${c.border} bg-accent/10`
      : c.style === "dashed"
      ? `${c.border} border-dashed`
      : c.border;
  return (
    <span className={`chip ${c.text} ${border}`} title={title ? c.hint : undefined}>
      {c.label}
    </span>
  );
}
