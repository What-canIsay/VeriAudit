import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { ShieldCheck, FolderGit2, Cloud, CloudOff, Box } from "lucide-react";
import { api } from "../api";

export default function Layout({ children }: { children: React.ReactNode }) {
  const loc = useLocation();
  const [cfg, setCfg] = useState<any>(null);
  useEffect(() => {
    api.config().then(setCfg).catch(() => {});
  }, []);

  return (
    <div className="min-h-dvh flex">
      {/* Sidebar */}
      <aside className="w-60 shrink-0 border-r border-border bg-surface/60 backdrop-blur-md flex flex-col">
        <div className="h-16 flex items-center gap-2.5 px-5 border-b border-border">
          <div className="w-8 h-8 rounded-lg bg-accent/15 border border-accent/30 grid place-items-center">
            <ShieldCheck className="w-5 h-5 text-accent" />
          </div>
          <div className="leading-tight">
            <div className="font-mono font-semibold tracking-tight">VeriAudit</div>
            <div className="text-[10px] text-faint">验证驱动的代码审计</div>
          </div>
        </div>

        <nav className="p-3 space-y-1 flex-1">
          <NavItem to="/" active={loc.pathname === "/"} icon={<FolderGit2 className="w-4 h-4" />}>
            项目
          </NavItem>
        </nav>

        <div className="p-3 border-t border-border space-y-2">
          {cfg && (
            <>
              <StatusRow
                icon={cfg.mock_mode ? <CloudOff className="w-3.5 h-3.5" /> : <Cloud className="w-3.5 h-3.5" />}
                label={cfg.mock_mode ? "Mock 模型模式" : `云端: ${cfg.model_tiers?.strong}`}
                tone={cfg.mock_mode ? "muted" : "accent"}
              />
              <StatusRow
                icon={<Box className="w-3.5 h-3.5" />}
                label={cfg.sandbox_available ? "沙箱就绪 (Docker)" : "沙箱不可用"}
                tone={cfg.sandbox_available ? "accent" : "muted"}
              />
            </>
          )}
          <div className="text-[10px] text-faint font-mono pt-1">v0.1.0 · 授权测试用途</div>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 min-w-0 flex flex-col">{children}</main>
    </div>
  );
}

function NavItem({ to, active, icon, children }: any) {
  return (
    <Link
      to={to}
      className={`flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm transition-colors ${
        active ? "bg-surface-3 text-fg" : "text-muted hover:text-fg hover:bg-surface-3/60"
      }`}
    >
      {icon}
      {children}
    </Link>
  );
}

function StatusRow({ icon, label, tone }: { icon: any; label: string; tone: "accent" | "muted" }) {
  return (
    <div className={`flex items-center gap-2 text-xs ${tone === "accent" ? "text-accent" : "text-faint"}`}>
      {icon}
      <span className="truncate">{label}</span>
    </div>
  );
}
