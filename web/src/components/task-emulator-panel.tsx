"use client";

import * as React from "react";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { Activity, EmulatorStatus } from "@/lib/types";
import { sseUrl } from "@/lib/api";

export function TaskEmulatorPanel({ taskId }: { taskId: string }) {
  const [status, setStatus] = React.useState<EmulatorStatus | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [reconnecting, setReconnecting] = React.useState(false);
  const cursor = React.useRef(0);
  const refresh = React.useCallback(() => api.emulator(taskId).then(setStatus).catch(() => setReconnecting(true)), [taskId]);
  React.useEffect(() => {
    void refresh();
    const es = new EventSource(sseUrl(`/api/exploration/activity/stream?task=${encodeURIComponent(taskId)}&since=${cursor.current}`));
    es.onopen = () => { setReconnecting(false); void refresh(); };
    es.onerror = () => setReconnecting(true);
    es.onmessage = (event) => {
      try {
        const activity = JSON.parse(event.data) as Activity;
        cursor.current = Math.max(cursor.current, activity.seq);
        if (activity.kind !== "emulator" || !activity.metadata?.emulator_state) return;
        const state = activity.metadata.emulator_state;
        if (state === "disabled" || state === "unavailable" || state === "starting" || state === "booting" || state === "ready" || state === "stopping" || state === "stopped" || state === "failed") {
          setStatus((current) => ({ task_id: taskId, ...current, state, progress: activity.metadata?.progress ?? current?.progress, reason: activity.is_error ? activity.summary : current?.reason }));
        }
      } catch { setReconnecting(true); }
    };
    return () => es.close();
  }, [refresh, taskId]);
  // Real Android boot takes minutes and emits no SSE until the backend polls
  // the sidecar. Poll only while a transition is in flight, so the panel
  // reaches ready/failed instead of freezing on "starting".
  React.useEffect(() => {
    const inFlight = status?.state === "starting" || status?.state === "booting" || status?.state === "stopping";
    if (!inFlight) return;
    const id = window.setInterval(() => { void refresh(); }, 4000);
    return () => window.clearInterval(id);
  }, [refresh, status?.state]);
  const change = async (action: "start" | "stop") => { setBusy(true); try { setStatus(action === "start" ? await api.startEmulator(taskId) : await api.stopEmulator(taskId)); } catch { await refresh(); } finally { setBusy(false); } };
  const state = status?.state ?? "starting";
  const label: Record<string, string> = { disabled: "Disabled", unavailable: "Unavailable", starting: "Starting", booting: "Booting", ready: "Ready", stopping: "Stopping", stopped: "Stopped", failed: "Failed" };
  return <section className="mb-4 rounded-lg border p-4" aria-label="Android emulator status">
    <div className="flex items-center justify-between gap-3"><div><h2 className="text-sm font-semibold">Android emulator</h2><p className="text-xs text-muted-foreground">Optional task-scoped runtime: {label[state] ?? "Unavailable"}</p></div>
      {state === "ready" || state === "booting" || state === "starting" ? <Button size="sm" variant="outline" disabled={busy || state === "starting" || state === "booting"} onClick={() => void change("stop")}>Stop</Button> : <Button size="sm" disabled={busy || state === "disabled" || state === "unavailable"} onClick={() => void change("start")}>Start</Button>}
    </div>{status?.progress !== undefined && <div className="mt-2 h-1.5 overflow-hidden rounded bg-muted"><div className="h-full bg-primary transition-all" style={{ width: `${Math.min(100, Math.max(0, status.progress))}%` }} /></div>}{(status?.reason || reconnecting) && <p className="mt-2 text-xs text-muted-foreground">{reconnecting ? "Reconnecting to task activity…" : status?.reason}</p>}
  </section>;
}
