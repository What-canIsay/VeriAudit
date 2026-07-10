// VeriAudit light design system — "取证仪 · The Trace".
// One scoped stylesheet, prefixed `.va`, shared by every page (Home / History / TaskConsole).
// Self-contained so it never fights the legacy dark globals. Pages append their own page CSS.

export const VA_CSS = `
.va {
  --paper:#F6F7F6; --panel:#FFFFFF; --panel2:#FAFBFB;
  --ink:#14181B; --muted:#5C6560; --faint:#93999A;
  --hair:#E1E4E3; --hair2:#EDEFEE; --grid:#00000009;
  --signal:#0B8A63; --signal-d:#0A754F; --signal-w:#E4F1EB;
  --crit:#B83227; --high:#C16A22; --med:#9C7A1A; --low:#4E77A8; --info:#8A9490;
  color:var(--ink); background-color:var(--paper); color-scheme:light;
  background-image:linear-gradient(var(--grid) 1px,transparent 1px),
    linear-gradient(90deg,var(--grid) 1px,transparent 1px);
  background-size:44px 44px;
  font-family:'IBM Plex Sans',system-ui,sans-serif; -webkit-font-smoothing:antialiased;
}
.va ::selection { background:var(--signal-w); }
.va *::-webkit-scrollbar { width:9px; height:9px; }
.va *::-webkit-scrollbar-thumb { background:#CDD3D1; border-radius:0; }
.va *::-webkit-scrollbar-track { background:transparent; }

.va-mono { font-family:'JetBrains Mono',monospace; }
.va-mark-sm { font-family:'Space Grotesk',sans-serif; font-weight:700; letter-spacing:.14em; font-size:14px; color:var(--ink); }
.va-dim { color:var(--faint); }
.va-mid { color:var(--faint); }
.va-ok { color:var(--signal); }
.va-no { color:var(--crit); }

/* pill / status chrome */
.va-pill { display:inline-flex; align-items:center; gap:8px; font-family:'JetBrains Mono',monospace;
  font-size:12px; color:var(--muted); border:1px solid var(--hair); background:#fff; padding:6px 12px; }
.va-pdot { width:7px; height:7px; border-radius:50%; background:var(--signal); flex:none; }
.va-chip { display:inline-flex; align-items:center; gap:6px; font-family:'JetBrains Mono',monospace;
  font-size:12px; padding:4px 9px; border:1px solid var(--hair); background:#fff; color:var(--muted); }

/* buttons — square, deliberate */
.va-btn { font-family:'IBM Plex Sans',sans-serif; font-size:14px; font-weight:600; cursor:pointer;
  border-radius:0; padding:11px 22px; display:inline-flex; align-items:center; gap:9px;
  border:1.5px solid transparent; background:none;
  transition:background .15s,color .15s,border-color .15s,transform .05s; }
.va-btn:active { transform:translateY(1px); }
.va-btn:disabled { opacity:.45; cursor:not-allowed; }
.va-btn-solid { background:var(--ink); color:#fff; }
.va-btn-solid:hover:not(:disabled) { background:#000; }
.va-btn-line { background:#fff; color:var(--ink); border-color:var(--ink); }
.va-btn-line:hover:not(:disabled) { background:var(--paper); }
.va-btn-danger { background:#fff; color:var(--crit); border-color:var(--crit); }
.va-btn-danger:hover:not(:disabled) { background:#FBEDEB; }
.va-btn-sm { font-size:13px; padding:8px 16px; }
.va-iconbtn { width:34px; height:34px; display:inline-flex; align-items:center; justify-content:center;
  border:1.5px solid var(--ink); background:#fff; color:var(--ink); cursor:pointer; border-radius:0;
  transition:background .12s; }
.va-iconbtn:hover:not(:disabled) { background:var(--paper); }
.va-iconbtn:disabled { opacity:.4; cursor:not-allowed; }
.va-arrow { font-family:'JetBrains Mono',monospace; font-weight:500; }

/* panels */
.va-card { background:var(--panel); border:1px solid var(--hair); }
.va-label { font-family:'JetBrains Mono',monospace; font-size:11px; letter-spacing:.14em;
  text-transform:uppercase; color:var(--faint); }

/* severity text + dot helpers */
.sv-critical { color:var(--crit); } .sd-critical { background:var(--crit); }
.sv-high { color:var(--high); }     .sd-high { background:var(--high); }
.sv-medium { color:var(--med); }    .sd-medium { background:var(--med); }
.sv-low { color:var(--low); }       .sd-low { background:var(--low); }
.sv-info { color:var(--info); }     .sd-info { background:var(--info); }

@keyframes vaDraw { to { stroke-dashoffset:0; } }
@keyframes vaPop { from { opacity:0; transform:scale(0); } to { opacity:1; transform:scale(1); } }
@keyframes vaPulse { 0%,100% { opacity:1; } 50% { opacity:.35; } }
@keyframes vaFade { from { opacity:0; transform:translateY(3px); } to { opacity:1; transform:none; } }
.va-pulse { animation:vaPulse 1.4s ease-in-out infinite; }
.va-fade { animation:vaFade .25s ease-out; }
`;

export const SEV_LABEL: Record<string, string> = {
  critical: "严重", high: "高危", medium: "中危", low: "低危", info: "信息",
};
export function sevClass(level?: string) {
  const l = level && SEV_LABEL[level] ? level : "info";
  return { label: SEV_LABEL[l], text: `sv-${l}`, dot: `sd-${l}`, key: l };
}

// confidence → the row action word used across list + history
export const CONF_LABEL: Record<string, string> = {
  CONFIRMED_DYNAMIC: "已复现",
  CONFIRMED_STATIC: "已确证",
  SUSPECTED: "疑似",
  REJECTED: "已排除",
};

export const STATUS_LABEL: Record<string, string> = {
  succeeded: "已完成", running: "进行中", paused: "已暂停", cancelling: "停止中",
  cancelled: "已停止", failed: "失败", queued: "排队中",
};
