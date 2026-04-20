import axios from "axios";

const API_KEY = import.meta.env.VITE_IDS_API_KEY ?? "ids-secret-key";
const BASE_URL = import.meta.env.VITE_IDS_BASE_URL ?? "http://localhost:6050";

const api = axios.create({
  baseURL: BASE_URL,
  headers: {
    "X-API-Key": API_KEY,
    "Content-Type": "application/json",
  },
});

export const idsApi = {
  predict: (data: any) => api.post("/predict/", data),
  processWorkflow: (alertData: any) => api.post("/workflow/process", alertData),
  getReports: () => api.get("/reports"),
  getReportById: (id: string) => api.get(`/reports/${id}`),
  getEvents: () => api.get("/events"),
  getEventsTimeseries: (window = 1800, buckets = 6) =>
    api.get("/events/timeseries", { params: { window, buckets } }),
  getStats: () => api.get("/events/stats"),
  getRemediationLogs: () => api.get("/remediation/logs"),
  // ── Autonomous SOC ────────────────────────────────────────────────────────
  generateAutoRules: (payload: { detection?: Record<string, any>; description?: string }) =>
    api.post("/soc/auto-rules", payload),
  getSandboxState: () => api.get("/sandbox/state"),
  clearSandbox: () => api.post("/sandbox/clear"),
  // ── Quarantine / Human Intervention ───────────────────────────────────────
  getQuarantine: () => api.get("/quarantine"),
  allowIp: (ip: string) => api.post(`/quarantine/${encodeURIComponent(ip)}/allow`),
  denyIp: (ip: string) => api.post(`/quarantine/${encodeURIComponent(ip)}/deny`),
  getBlockedIps: () => api.get("/blocked-ips"),
  unblockIp: (ip: string) => api.delete(`/blocked-ips/${encodeURIComponent(ip)}`),
  // ── Live Capture ──────────────────────────────────────────────────────────
  getInterfaces: () => api.get("/interfaces"),
  startLiveCapture: (interface_: string, duration_per_cycle = 5) =>
    api.post("/start-live-capture", { interface: interface_, duration_per_cycle }),
  stopLiveCapture: () => api.post("/stop-live-capture"),
  getCaptureStatus: () => api.get("/capture-status"),
};

export default api;
