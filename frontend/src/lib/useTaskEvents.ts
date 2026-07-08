import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import type { Counts } from "../types";

const EVENT_NAMES = [
  "task.status", "agent.started", "agent.finished", "agent.thinking",
  "agent.reasoning", "agent.llm_output",
  "tool.invoked", "tool.result", "plan.ready", "recon.ready",
  "candidate.recorded", "trace.ready", "provision.ready", "provision.failed",
  "sandbox.poc_attempt",
  "finding.confirmed", "finding.rejected", "verify.ready", "report.ready",
  "task.finished",
];

export interface LiveEvent {
  event: string;
  data: any;
  ts: number;
  seq: number;
}

export function useTaskEvents(taskId: string | undefined, live: boolean = true) {
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [status, setStatus] = useState<string>("");
  const [phase, setPhase] = useState<string>("");
  const [counts, setCounts] = useState<Counts>({});
  const [finished, setFinished] = useState(false);
  const [findingIds, setFindingIds] = useState<string[]>([]);
  const seq = useRef(0);
  const es = useRef<EventSource | null>(null);

  useEffect(() => {
    if (!taskId || !live) return;   // only subscribe SSE for live (running) tasks
    setEvents([]);
    setFinished(false);
    setFindingIds([]);
    const source = new EventSource(api.eventsUrl(taskId));
    es.current = source;

    const onEvt = (name: string) => (e: MessageEvent) => {
      let data: any = {};
      try {
        data = JSON.parse(e.data);
      } catch {
        /* heartbeat */
      }
      setEvents((prev) => [...prev, { event: name, data, ts: Date.now(), seq: seq.current++ }]);
      if (name === "task.status") {
        setStatus(data.status);
        setPhase(data.phase);
        if (data.counts) setCounts(data.counts);
      }
      if (name === "finding.confirmed" && data.finding_id) {
        setFindingIds((p) => (p.includes(data.finding_id) ? p : [...p, data.finding_id]));
      }
      if (name === "task.finished") {
        if (data.counts) setCounts(data.counts);
        setStatus(data.error ? "failed" : "succeeded");
        setFinished(true);
        source.close();
      }
    };

    EVENT_NAMES.forEach((n) => source.addEventListener(n, onEvt(n) as any));
    source.onerror = () => {
      /* browser auto-reconnects; if server closed we already stopped */
    };
    return () => source.close();
  }, [taskId, live]);

  return { events, status, phase, counts, finished, findingIds };
}

// Convert persisted DB timeline (agent_runs + tool_invocations) into renderable
// events so a FINISHED task can be re-opened and reviewed (even after a restart).
export function timelineToEvents(items: any[]): LiveEvent[] {
  const out: LiveEvent[] = [];
  let seq = 0;
  for (const it of items || []) {
    const ts = it.ts ? Date.parse(it.ts) : 0;
    if (it.kind === "agent") {
      out.push({ event: "agent.started", data: { agent: it.agent, node: it.node, run_id: it.run_id }, ts, seq: seq++ });
    } else if (it.kind === "tool") {
      if (it.tool === "llm_call") {
        const r = it.summary?.reasoning;
        const o = it.summary?.output;
        if (r) out.push({ event: "agent.reasoning", data: { agent: it.agent, text: r }, ts, seq: seq++ });
        if (o) out.push({ event: "agent.llm_output", data: { text: o }, ts, seq: seq++ });
      } else {
        out.push({ event: "tool.invoked", data: { tool: it.tool, agent: it.agent, args_brief: {} }, ts, seq: seq++ });
      }
    }
  }
  return out;
}
