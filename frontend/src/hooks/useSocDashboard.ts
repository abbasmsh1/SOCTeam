import { useState, useEffect } from 'react';
import { idsApi } from '../utils/api';

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

export const useSocDashboard = (pollingInterval = 2000) => {
  const [reports, setReports] = useState<Report[]>([]);
  const [stats, setStats] = useState<SocStats>({
    packets_per_second: 0,
    pending_alerts: 0,
    confirmed_threats: 0,
    active_agents: 0
  });
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [reportsRes, statsRes] = await Promise.all([
          idsApi.getReports(),
          idsApi.getStats()
        ]);
        
        // Ensure reports are sorted by most recent
        const sortedReports = (reportsRes.data as Report[]).sort(
          (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
        );
        
        setReports(sortedReports);
        setStats(statsRes.data);
        setError(null);
      } catch (err) {
        console.error("Dashboard refresh failed:", err);
        setError("Network connection issue - Backend unreachable");
      } finally {
        setIsLoading(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, pollingInterval);
    return () => clearInterval(interval);
  }, [pollingInterval]);

  const latestReport = reports.length > 0 ? reports[0] : null;

  return {
    reports,
    stats,
    latestReport,
    isLoading,
    error
  };
};
