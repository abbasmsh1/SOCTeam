import axios from 'axios';

const BASE_URL  = import.meta.env.VITE_IDS_BASE_URL      ?? 'http://localhost:6050';
const READ_KEY  = import.meta.env.VITE_IDS_API_KEY       ?? 'ids-secret-key';
const ADMIN_KEY = import.meta.env.VITE_IDS_ADMIN_API_KEY ?? '';

/**
 * The operator console is a privileged interface — if the admin key is
 * configured, use it for everything (admin is a superset of read-scope on
 * the server, so one key works for both tiers). Otherwise fall back to the
 * read key; admin-only endpoints will 403 in that mode, which is the
 * expected behaviour for read-only deployments.
 */
const EFFECTIVE_KEY = ADMIN_KEY || READ_KEY;

if (!ADMIN_KEY && typeof console !== 'undefined') {
  console.warn(
    '[idsApi] VITE_IDS_ADMIN_API_KEY is not set — admin endpoints ' +
    '(/soc/auto-rules, /sandbox/clear, /quarantine/*, /start-live-capture, ' +
    'etc.) will fail with 403. Set it in frontend/.env to enable full operator access.',
  );
}

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 30_000,
  headers: {
    'X-API-Key': EFFECTIVE_KEY,
    'Content-Type': 'application/json',
  },
});

export const idsApi = {
  // ── Core prediction & workflow ───────────────────────────────────────────
  predict:           (data: any)       => api.post('/predict/', data),
  processWorkflow:   (alertData: any)  => api.post('/workflow/process', alertData),

  // ── Reports ──────────────────────────────────────────────────────────────
  getReports:        ()                => api.get('/reports'),
  getReportById:     (id: string)      => api.get(`/reports/${id}`),

  // ── Events / live feed ───────────────────────────────────────────────────
  getEvents:         ()                => api.get('/events'),
  getEventsTimeseries: (window = 1800, buckets = 6) =>
                                         api.get('/events/timeseries', { params: { window, buckets } }),
  getStats:          ()                => api.get('/events/stats'),

  // ── Aggregated snapshot ──────────────────────────────────────────────────
  /** Single-call dashboard snapshot: stats + top threats + sandbox + capture. */
  getOverview:       ()                => api.get('/overview'),

  /** Top attacking source IPs within the given window (seconds). */
  getTopThreats:     (windowSec = 3600, limit = 10) =>
                                         api.get('/threats/top', { params: { window: windowSec, limit } }),

  // ── Remediation ──────────────────────────────────────────────────────────
  getRemediationLogs: ()               => api.get('/remediation/logs'),

  // ── Autonomous SOC (admin) ───────────────────────────────────────────────
  generateAutoRules: (payload: { detection?: Record<string, any>; description?: string }) =>
                                         api.post('/soc/auto-rules', payload),
  getSandboxState:   ()                => api.get('/sandbox/state'),
  clearSandbox:      ()                => api.post('/sandbox/clear'),

  // ── Quarantine / Human Intervention ──────────────────────────────────────
  getQuarantine:     ()                => api.get('/quarantine'),
  allowIp:           (ip: string)      => api.post(`/quarantine/${encodeURIComponent(ip)}/allow`),
  denyIp:            (ip: string)      => api.post(`/quarantine/${encodeURIComponent(ip)}/deny`),
  getBlockedIps:     ()                => api.get('/blocked-ips'),
  unblockIp:         (ip: string)      => api.delete(`/blocked-ips/${encodeURIComponent(ip)}`),

  // ── Live Capture (admin) ─────────────────────────────────────────────────
  getInterfaces:     ()                => api.get('/interfaces'),
  startLiveCapture:  (interface_: string, duration_per_cycle = 5) =>
                                         api.post('/start-live-capture', { interface: interface_, duration_per_cycle }),
  stopLiveCapture:   ()                => api.post('/stop-live-capture'),
  getCaptureStatus:  ()                => api.get('/capture-status'),

  // ── Reinforcement Learning ───────────────────────────────────────────────
  getRLStats:        ()                => api.get('/rl/stats'),
  getRLPolicy:       ()                => api.get('/rl/policy'),
  triggerRLTrain:    (body = { limit: 500, epochs: 3, lr: 1e-4, dry_run: false }) =>
                                         api.post('/rl/train', body),

  // ── Incident Graph ───────────────────────────────────────────────────────
  getGraphSummary:   ()                => api.get('/graph/summary'),
  getGraphForIP:     (ip: string, limit = 25) =>
                                         api.get(`/graph/ip/${encodeURIComponent(ip)}`, { params: { limit } }),

  // ── Self-IP allowlist ────────────────────────────────────────────────────
  getSelfIps:        ()                => api.get('/self-ips'),
  refreshSelfIps:    ()                => api.post('/self-ips/refresh'),
};

export default api;
