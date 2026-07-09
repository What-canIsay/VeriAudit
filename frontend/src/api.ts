import type { Finding, Project, Task, TimelineItem } from "./types";

const BASE = "/api/v1";

async function j<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const t = await res.text();
    throw new Error(`${res.status}: ${t}`);
  }
  return res.json();
}

export const api = {
  config: () => fetch(`${BASE}/config`).then((r) => j<any>(r)),

  listProjects: () => fetch(`${BASE}/projects`).then((r) => j<Project[]>(r)),
  getProject: (id: string) => fetch(`${BASE}/projects/${id}`).then((r) => j<Project>(r)),
  createProject: (body: { name: string; source_type: string; source_ref: string }) =>
    fetch(`${BASE}/projects`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }).then((r) => j<Project>(r)),
  updateProject: (id: string, body: { name?: string; source_type?: string; source_ref?: string }) =>
    fetch(`${BASE}/projects/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }).then((r) => j<Project>(r)),

  createTask: (pid: string, body: { depth: string }) =>
    fetch(`${BASE}/projects/${pid}/tasks`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }).then((r) => j<Task>(r)),
  getTask: (id: string) => fetch(`${BASE}/tasks/${id}`).then((r) => j<Task>(r)),
  pauseTask: (id: string) => fetch(`${BASE}/tasks/${id}/pause`, { method: "POST" }).then((r) => j<Task>(r)),
  resumeTask: (id: string) => fetch(`${BASE}/tasks/${id}/resume`, { method: "POST" }).then((r) => j<Task>(r)),
  cancelTask: (id: string) => fetch(`${BASE}/tasks/${id}/cancel`, { method: "POST" }).then((r) => j<Task>(r)),
  timeline: (id: string) => fetch(`${BASE}/tasks/${id}/timeline`).then((r) => j<TimelineItem[]>(r)),
  findings: (id: string, confidence?: string) =>
    fetch(`${BASE}/tasks/${id}/findings${confidence ? `?confidence=${encodeURIComponent(confidence)}` : ""}`).then(
      (r) => j<Finding[]>(r)
    ),
  finding: (id: string) => fetch(`${BASE}/findings/${id}`).then((r) => j<Finding>(r)),
  report: (id: string, format: string) =>
    fetch(`${BASE}/tasks/${id}/report?format=${format}`, { method: "POST" }).then((r) =>
      j<{ format: string; content: string }>(r)
    ),

  eventsUrl: (id: string) => `${BASE}/tasks/${id}/events`,
};
