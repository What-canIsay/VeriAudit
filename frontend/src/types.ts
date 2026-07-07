export interface Project {
  id: string;
  name: string;
  source_type: string;
  source_ref: string;
  commit_sha?: string | null;
  languages: Record<string, number>;
  status: string;
  created_at?: string;
  tasks?: Task[];
}

export interface Task {
  id: string;
  project_id: string;
  depth: string;
  status: string;
  phase: string;
  counts: Counts;
  error?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  created_at?: string | null;
}

export interface Counts {
  confirmed_dynamic?: number;
  confirmed_static?: number;
  suspected?: number;
  rejected?: number;
  total_findings?: number;
  by_severity?: Record<string, number>;
}

export interface CodeLoc {
  file?: string;
  line?: number;
  function?: string | null;
  snippet?: string;
}

export interface TaintHop {
  location: CodeLoc;
  variable?: string;
  transform?: string;
  note?: string;
}

export interface Evidence {
  entry_point?: CodeLoc | null;
  source?: CodeLoc | null;
  sink?: CodeLoc | null;
  taint_path: TaintHop[];
  sanitizers: any[];
  reachability: Record<string, any>;
  static_verdict: Record<string, any>;
  dynamic_verification?: Record<string, any> | null;
}

export interface Artifact {
  id: string;
  kind: string;
  content: string;
  meta: Record<string, any>;
}

export interface Finding {
  id: string;
  task_id: string;
  vuln_type: string;
  title: string;
  confidence: string;
  severity: { level?: string; score?: number; vector?: string };
  cvss_vector?: string;
  status: string;
  remediation?: string;
  evidence?: Evidence | null;
  artifacts?: Artifact[];
  created_at?: string;
}

export interface TimelineItem {
  kind: "agent" | "tool";
  ts?: string | null;
  agent?: string;
  node?: string;
  status?: string;
  tool?: string;
  ok?: boolean;
  summary?: Record<string, any>;
  run_id?: string | null;
  output?: Record<string, any>;
}

export interface SSEEvent {
  event: string;
  data: any;
}
