/**
 * BlockedIpsTable.tsx
 * Displays a live table of enforcement actions (BLOCK_IP, RATE_LIMIT, etc.)
 * executed by the SOC Remediation Engine. Polls the backend every 5 seconds.
 */

import { useEffect, useState } from 'react';
import { ShieldAlert, Clock, Target, Activity } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { idsApi } from '../utils/api';
import type { RemediationLog } from '../hooks/useSocStream';

const POLL_INTERVAL_MS = 5000;

interface Props {
  logs?: RemediationLog[];
}

export default function BlockedIpsTable({ logs: logsProp }: Props = {}) {
  const [logs, setLogs] = useState<RemediationLog[]>(logsProp ?? []);
  const [loading, setLoading] = useState(!logsProp);

  useEffect(() => {
    if (logsProp !== undefined) {
      setLogs(logsProp);
      setLoading(false);
      return;
    }
    const fetchLogs = async () => {
      try {
        const res = await idsApi.getRemediationLogs();
        setLogs(Array.isArray(res.data) ? res.data : []);
      } catch (error) {
        console.error('Failed to fetch remediation logs:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchLogs();
    const interval = setInterval(fetchLogs, POLL_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [logsProp]);

  /** Green = completed, amber = pending, neutral = other. */
  const getStatusColor = (status?: string): string => {
    switch (status) {
      case 'EXECUTED':
      case 'SIMULATED_SUCCESS':
        return 'text-benign border-benign shadow-benign/20';
      case 'PENDING':
        return 'text-warning border-warning shadow-warning/20';
      default:
        return 'text-slate-400 border-slate-700';
    }
  };

  /** Red = block, amber = rate limit, blue = other. */
  const getActionColor = (action?: string): string => {
    const safeAction = (action ?? '').toUpperCase();
    if (safeAction.includes('BLOCK')) return 'text-malicious bg-malicious/10 border-malicious/30';
    if (safeAction.includes('LIMIT')) return 'text-warning bg-warning/10 border-warning/30';
    return 'text-primary bg-primary/10 border-primary/30';
  };

  return (
    <div className="hud-card border-malicious/20 relative group overflow-hidden mt-8">
      {/* Header */}
      <div className="flex items-center justify-between mb-8 border-b border-white/5 pb-4">
        <h3 className="text-sm font-black text-white uppercase tracking-widest flex items-center gap-2">
            <ShieldAlert className="text-malicious" size={18} />
            Enforcement Actions & Blocked Targets
        </h3>
        <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 text-xs font-mono text-slate-400 border border-white/10 px-3 py-1 bg-black/40">
                Total Interventions: <span className="text-white font-bold">{logs.length}</span>
            </div>
            <span className="text-[10px] font-mono text-malicious/60 uppercase animate-pulse">
                [MONITOR_ACTIVE]
            </span>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
            <thead>
                <tr className="border-b border-white/10 text-[10px] font-mono text-slate-500 uppercase tracking-wider">
                    <th className="pb-3 pl-4 font-normal">Timestamp</th>
                    <th className="pb-3 font-normal">Action Taken</th>
                    <th className="pb-3 font-normal">Target / IP</th>
                    <th className="pb-3 font-normal hidden md:table-cell">Duration</th>
                    <th className="pb-3 font-normal hidden lg:table-cell">Reason / Trigger</th>
                    <th className="pb-3 pr-4 text-right font-normal">Execution Status</th>
                </tr>
            </thead>
            <tbody>
                <AnimatePresence initial={false}>
                {loading && logs.length === 0 ? (
                    <tr><td colSpan={6} className="py-12 text-center text-slate-500 font-mono text-[10px] uppercase tracking-widest">
                        Establishing connection to remediation engine...
                    </td></tr>
                ) : logs.length > 0 ? (
                    logs.map((log, idx) => (
                        <motion.tr key={`${log.timestamp ?? 'unknown'}-${idx}`} initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}
                            className="border-b border-white/5 hover:bg-white/5 transition-colors group">
                            {/* Timestamp */}
                            <td className="py-4 pl-4 align-top">
                                <div className="flex items-center gap-2 text-slate-400">
                                    <Clock size={12} className="opacity-50" />
                                    <span className="text-[11px] font-mono">
                                        {log.timestamp
                                          ? new Date(log.timestamp).toLocaleString([], { dateStyle: 'short', timeStyle: 'medium' })
                                          : 'Unknown time'}
                                    </span>
                                </div>
                            </td>
                            {/* Action badge */}
                            <td className="py-4 align-top">
                                <span className={`text-[10px] font-bold font-mono px-2 py-1 border ${getActionColor(log.action)}`}>
                                    {log.action ?? 'UNKNOWN_ACTION'}
                                </span>
                            </td>
                            {/* Target IP */}
                            <td className="py-4 align-top">
                                <div className="flex items-center gap-2">
                                    <Target size={12} className="text-slate-500 hidden sm:block" />
                                    <span className="text-[11px] font-mono text-white bg-black/50 px-2 py-0.5 border border-white/10">
                                        {log.target ?? 'Unknown target'}
                                    </span>
                                </div>
                            </td>
                            {/* Duration */}
                            <td className="py-4 align-top hidden md:table-cell">
                                <span className="text-[11px] font-mono text-slate-400">{log.duration || 'N/A'}</span>
                            </td>
                            {/* Reason */}
                            <td className="py-4 align-top hidden lg:table-cell">
                                <div className="text-[11px] text-slate-400 max-w-xs truncate" title={log.reason ?? ''}>{log.reason ?? 'No reason provided'}</div>
                            </td>
                            {/* Status + auto-pilot */}
                            <td className="py-4 pr-4 align-top text-right">
                                <div className="flex items-center justify-end gap-2">
                                    <span className={`text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 border ${getStatusColor(log.status)}`}>
                                        {log.status === 'SIMULATED_SUCCESS' ? 'SIMULATED' : (log.status ?? 'UNKNOWN')}
                                    </span>
                                    {log.auto_pilot && (
                                        <span title="Auto-pilot active"><Activity size={12} className="text-primary animate-pulse" /></span>
                                    )}
                                </div>
                            </td>
                        </motion.tr>
                    ))
                ) : (
                    <tr><td colSpan={6} className="py-12 text-center opacity-30">
                        <p className="text-[10px] italic font-mono uppercase tracking-widest text-white">No active enforcements or blocked targets in ledger.</p>
                    </td></tr>
                )}
                </AnimatePresence>
            </tbody>
        </table>
      </div>

      {/* Decorative HUD border corners */}
      <div className="absolute top-0 left-0 w-2 h-2 border-t border-l border-malicious/50" />
      <div className="absolute top-0 right-0 w-2 h-2 border-t border-r border-malicious/50" />
      <div className="absolute bottom-0 left-0 w-2 h-2 border-b border-l border-malicious/50" />
      <div className="absolute bottom-0 right-0 w-2 h-2 border-b border-r border-malicious/50" />
    </div>
  );
}
