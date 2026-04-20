import { useEffect, useRef, useState } from 'react';

export interface Report {
  id: string;
  name: string;
  created_at: string;
  escalated_to_tier2?: boolean;
  escalated_to_tier3?: boolean;
  war_room_triggered?: boolean;
  final_severity?: string;
}

export interface SocStats {
  packets_per_second: number;
  pending_alerts: number;
  confirmed_threats: number;
  active_agents: number;
}

export interface TrafficPoint {
  name: string;
  flows: number;
}

export interface FirewallRule {
  rule_id?: string;
  action?: string;
  source_ip?: string;
  destination_ip?: string;
  port?: number | string;
  protocol?: string;
  description?: string;
  created_at?: string;
}

export interface SandboxState {
  blocked_ips: string[];
  firewall_rules: FirewallRule[];
  rate_limited_hosts: string[];
  total_actions: number;
}

export interface RemediationLog {
  id?: string;
  action?: string;
  target?: string;
  reason?: string;
  status?: string;
  timestamp?: string;
  duration?: string;
  auto_pilot?: boolean;
}

export interface SocStreamState {
  reports: Report[];
  stats: SocStats;
  traffic: TrafficPoint[];
  sandbox: SandboxState;
  remediationLogs: RemediationLog[];
  latestReport: Report | null;
  error: string | null;
  connected: boolean;
}

const EMPTY_STATE: SocStreamState = {
  reports: [],
  stats: { packets_per_second: 0, pending_alerts: 0, confirmed_threats: 0, active_agents: 0 },
  traffic: [],
  sandbox: { blocked_ips: [], firewall_rules: [], rate_limited_hosts: [], total_actions: 0 },
  remediationLogs: [],
  latestReport: null,
  error: null,
  connected: false,
};

const BASE_URL = import.meta.env.VITE_IDS_BASE_URL ?? 'http://localhost:6050';
const API_KEY = import.meta.env.VITE_IDS_API_KEY ?? 'ids-secret-key';

export function useSocStream(): SocStreamState {
  const [state, setState] = useState<SocStreamState>(EMPTY_STATE);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    const url = `${BASE_URL}/events/stream?x_api_key=${encodeURIComponent(API_KEY)}`;
    const es = new EventSource(url);
    esRef.current = es;

    es.onopen = () => {
      setState((prev) => ({ ...prev, connected: true, error: null }));
    };

    es.onmessage = (evt) => {
      try {
        const payload = JSON.parse(evt.data);
        const reports = Array.isArray(payload.reports) ? payload.reports : [];
        const sortedReports = (reports as Report[]).slice().sort(
          (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
        );
        setState({
          reports: sortedReports,
          stats: payload.stats ?? EMPTY_STATE.stats,
          traffic: Array.isArray(payload.timeseries) ? payload.timeseries : [],
          sandbox: {
            blocked_ips: payload.sandbox?.blocked_ips ?? [],
            firewall_rules: payload.sandbox?.firewall_rules ?? [],
            rate_limited_hosts: payload.sandbox?.rate_limited_hosts ?? [],
            total_actions: payload.sandbox?.total_actions ?? 0,
          },
          remediationLogs: Array.isArray(payload.remediation_logs) ? payload.remediation_logs : [],
          latestReport: sortedReports[0] ?? null,
          error: null,
          connected: true,
        });
      } catch (err) {
        console.error('[useSocStream] parse error', err);
      }
    };

    es.onerror = () => {
      setState((prev) => ({
        ...prev,
        connected: false,
        error: 'Stream disconnected — retrying',
      }));
    };

    return () => {
      es.close();
      esRef.current = null;
    };
  }, []);

  return state;
}
