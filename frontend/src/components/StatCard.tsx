export function StatCard({
  label, value, tone = "fg", sub,
}: {
  label: string;
  value: React.ReactNode;
  tone?: string;
  sub?: string;
}) {
  const toneMap: Record<string, string> = {
    fg: "text-fg", accent: "text-accent", critical: "text-critical",
    high: "text-high", medium: "text-medium", low: "text-low", muted: "text-muted",
  };
  return (
    <div className="card px-4 py-3">
      <div className="label mb-1">{label}</div>
      <div className={`text-2xl font-mono font-semibold ${toneMap[tone] || "text-fg"}`}>{value}</div>
      {sub && <div className="text-[11px] text-faint mt-0.5">{sub}</div>}
    </div>
  );
}

export function SeverityBar({ by }: { by: Record<string, number> }) {
  const order = ["critical", "high", "medium", "low", "info"];
  const colors: Record<string, string> = {
    critical: "bg-critical", high: "bg-high", medium: "bg-medium", low: "bg-low", info: "bg-info",
  };
  const total = order.reduce((s, k) => s + (by[k] || 0), 0) || 1;
  return (
    <div className="flex h-2 rounded-full overflow-hidden bg-surface-3">
      {order.map((k) =>
        by[k] ? (
          <div key={k} className={colors[k]} style={{ width: `${((by[k] || 0) / total) * 100}%` }} title={`${k}: ${by[k]}`} />
        ) : null
      )}
    </div>
  );
}
