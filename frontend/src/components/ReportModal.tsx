import { useEffect, useState } from "react";
import { X, Copy, Download, Check, Loader2 } from "lucide-react";
import { api } from "../api";

const FORMATS = [
  { key: "markdown", label: "Markdown", ext: "md" },
  { key: "json", label: "JSON", ext: "json" },
  { key: "sarif", label: "SARIF", ext: "sarif" },
];

export default function ReportModal({ taskId, onClose }: { taskId: string; onClose: () => void }) {
  const [fmt, setFmt] = useState("markdown");
  const [content, setContent] = useState("");
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    setLoading(true);
    api.report(taskId, fmt).then((r) => setContent(r.content)).catch((e) => setContent(String(e)))
      .finally(() => setLoading(false));
  }, [taskId, fmt]);

  function copy() {
    navigator.clipboard.writeText(content);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }
  function download() {
    const ext = FORMATS.find((f) => f.key === fmt)?.ext || "txt";
    const blob = new Blob([content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `veriaudit-report.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <>
      <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 animate-fade-in" onClick={onClose} />
      <div className="fixed inset-0 z-50 grid place-items-center p-6 pointer-events-none">
        <div className="card w-full max-w-4xl h-[80vh] flex flex-col pointer-events-auto animate-fade-in bg-surface">
          <div className="flex items-center justify-between px-5 py-3.5 border-b border-border shrink-0">
            <span className="font-medium">审计报告</span>
            <div className="flex items-center gap-2">
              <div className="flex gap-1 bg-surface-2 rounded-lg p-1">
                {FORMATS.map((f) => (
                  <button key={f.key} onClick={() => setFmt(f.key)}
                    className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                      fmt === f.key ? "bg-surface-3 text-fg" : "text-muted hover:text-fg"}`}>
                    {f.label}
                  </button>
                ))}
              </div>
              <button className="btn-ghost px-2" onClick={copy}>{copied ? <Check className="w-4 h-4 text-accent" /> : <Copy className="w-4 h-4" />}</button>
              <button className="btn-ghost px-2" onClick={download}><Download className="w-4 h-4" /></button>
              <button className="btn-ghost px-2" onClick={onClose}><X className="w-4 h-4" /></button>
            </div>
          </div>
          <div className="flex-1 min-h-0 overflow-auto p-5">
            {loading ? (
              <div className="flex items-center justify-center h-full text-faint"><Loader2 className="w-5 h-5 animate-spin" /></div>
            ) : (
              <pre className="text-xs font-mono whitespace-pre-wrap text-muted leading-relaxed">{content}</pre>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
