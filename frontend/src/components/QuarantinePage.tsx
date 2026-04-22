/**
 * QuarantinePage.tsx
 * ==================
 * Human-in-the-loop console for the SOC.
 *
 * Section 1: Pending Human Review  (status === "PENDING_HUMAN")
 *   - ALLOW  → POST /quarantine/{ip}/allow   (whitelists)
 *   - DENY   → POST /quarantine/{ip}/deny    (permanent block + sandbox BLOCK_IP)
 *
 * Section 2: Active Blocks (polled from GET /blocked-ips)
 *   - UNBLOCK → DELETE /blocked-ips/{ip}
 *
 * Auto-refreshes every 3 seconds.
 */

import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Check, Ban, Trash2, ArrowLeft, Shield, AlertTriangle, RefreshCw, Brain } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { idsApi } from '../utils/api';

interface QuarantineEntry {
  id: string;
  ip: string;
  status: 'PENDING_HUMAN' | 'BLOCKED' | string;
  threat_label?: string;
  confidence?: number;
  reason?: string;
  timestamp?: string;
  reasoning?: {
    decision?: string;
    score?: number;
    factors?: string[];
  };
  raw_flow?: Record<string, unknown>;
}

interface BlockRecord {
  ip: string;
  reason?: string;
  duration?: string;
  severity?: string;
  blocked_at?: string;
  expires_at?: string | null;
}

interface BlockListResponse {
  total_blocked?: number;
  blocked_ips?: Record<string, BlockRecord>;
  whitelisted_count?: number;
  reputation_cache_size?: number;
  timestamp?: string;
}

interface Toast {
  id: string;
  message: string;
  tone: 'success' | 'error';
}

const POLL_INTERVAL_MS = 3000;

function fmtTime(iso?: string): string {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString([], { dateStyle: 'short', timeStyle: 'medium' });
  } catch {
    return iso;
  }
}

function abuseScore(entry: QuarantineEntry): string {
  const factors = entry.reasoning?.factors ?? [];
  const hit = factors.find((f) => f.toLowerCase().includes('abuseipdb'));
  return hit ?? '—';
}

export default function QuarantinePage() {
  const [entries, setEntries] = useState<QuarantineEntry[]>([]);
  const [blocked, setBlocked] = useState<BlockRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [lastError, setLastError] = useState<string | null>(null);
  const [rlStats, setRlStats] = useState<{ total?: number; avg_reward?: number; by_status?: Record<string, number> } | null>(null);

  const pushToast = useCallback((message: string, tone: Toast['tone'] = 'success') => {
    const id = crypto.randomUUID();
    setToasts((prev) => [...prev, { id, message, tone }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 3500);
  }, []);

  const fetchAll = useCallback(async () => {
    try {
      const [qRes, bRes, rlRes] = await Promise.all([
        idsApi.getQuarantine(),
        idsApi.getBlockedIps(),
        idsApi.getRLStats().catch(() => ({ data: null })),
      ]);
      setEntries(Array.isArray(qRes.data) ? qRes.data : []);
      const bPayload = bRes.data as BlockListResponse;
      const blockedIps = bPayload?.blocked_ips ?? {};
      setBlocked(
        Object.entries(blockedIps).map(([ip, rec]) => ({
          ...(rec as BlockRecord),
          ip,
        }))
      );
      if (rlRes?.data && rlRes.data.enabled !== false) {
        setRlStats(rlRes.data);
      }
      setLastError(null);
    } catch (err: any) {
      console.error('[QuarantinePage] fetch failed:', err);
      setLastError(err?.message ?? 'fetch failed');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, POLL_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [fetchAll]);

  const pending = entries.filter((e) => e.status === 'PENDING_HUMAN');

  const onAllow = async (ip: string) => {
    try {
      await idsApi.allowIp(ip);
      pushToast(`${ip} allowed and whitelisted`);
      setEntries((prev) => prev.filter((e) => e.ip !== ip));
    } catch (err: any) {
      pushToast(`Allow failed: ${err?.message ?? 'error'}`, 'error');
    }
  };

  const onDeny = async (ip: string) => {
    try {
      await idsApi.denyIp(ip);
      pushToast(`${ip} blocked`);
      setEntries((prev) => prev.filter((e) => e.ip !== ip));
      fetchAll();
    } catch (err: any) {
      pushToast(`Deny failed: ${err?.message ?? 'error'}`, 'error');
    }
  };

  const onUnblock = async (ip: string) => {
    try {
      await idsApi.unblockIp(ip);
      pushToast(`${ip} unblocked`);
      setBlocked((prev) => prev.filter((b) => b.ip !== ip));
    } catch (err: any) {
      pushToast(`Unblock failed: ${err?.message ?? 'error'}`, 'error');
    }
  };

  return (
    <div className="min-h-screen p-6 space-y-8 bg-transparent">
      {/* Header */}
      <header className="flex items-center justify-between border-b border-white/10 pb-6">
        <div>
          <Link
            to="/"
            className="flex items-center gap-2 text-[11px] font-mono text-slate-500 hover:text-primary uppercase tracking-widest mb-2"
          >
            <ArrowLeft size={12} /> Back to Mission Control
          </Link>
          <h1 className="text-3xl font-black text-white tracking-widest uppercase italic">
            QUARANTINE <span className="text-warning">/ HUMAN INTERVENTION</span>
          </h1>
          <p className="text-slate-500 text-xs font-mono uppercase tracking-tighter mt-1">
            Pending reviews: <span className="text-warning">{pending.length}</span> · Active
            blocks: <span className="text-malicious">{blocked.length}</span>
          </p>
        </div>
        <button
          onClick={fetchAll}
          className="flex items-center gap-2 text-[11px] font-bold font-mono uppercase tracking-widest px-3 py-2 border border-white/10 text-slate-400 hover:text-primary hover:border-primary/40 transition-colors"
        >
          <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
          Refresh
        </button>
      </header>

      {lastError && (
        <div className="border border-malicious/40 bg-malicious/10 px-3 py-2 text-[11px] font-mono text-malicious">
          Backend error: {lastError}
        </div>
      )}

      {rlStats && (
        <div className="hud-card border-primary/10 bg-primary/5 flex items-center gap-6 py-3 px-4">
          <div className="flex items-center gap-2">
            <Brain size={14} className="text-primary" />
            <span className="text-[10px] font-mono uppercase tracking-widest text-slate-500">
              Your decisions train the model
            </span>
          </div>
          <div className="flex items-center gap-4 ml-auto text-[11px] font-mono">
            <span>
              <span className="text-slate-500">buffer </span>
              <span className="text-white font-bold">{rlStats.total ?? 0}</span>
            </span>
            <span>
              <span className="text-slate-500">labeled </span>
              <span className="text-benign font-bold">{rlStats.by_status?.labeled ?? 0}</span>
            </span>
            <span>
              <span className="text-slate-500">avg reward </span>
              <span className={`font-bold ${((rlStats.avg_reward ?? 0) > 0.3) ? 'text-benign' : (rlStats.avg_reward ?? 0) < -0.3 ? 'text-malicious' : 'text-warning'}`}>
                {(rlStats.avg_reward ?? 0).toFixed(3)}
              </span>
            </span>
          </div>
        </div>
      )}

      {/* Section 1: Pending Human Review */}
      <section className="hud-card border-warning/20 relative overflow-hidden">
        <div className="flex items-center justify-between mb-6 border-b border-white/5 pb-4">
          <h2 className="text-sm font-black text-white uppercase tracking-widest flex items-center gap-2">
            <AlertTriangle className="text-warning" size={16} />
            Section 1 — Pending Human Review
          </h2>
          <span className="text-[10px] font-mono text-warning/60 uppercase">
            {pending.length} WAITING
          </span>
        </div>
        {pending.length === 0 ? (
          <div className="text-center py-12 border border-dashed border-white/10 opacity-40 italic text-[11px] font-mono uppercase tracking-widest">
            NO PENDING INTERVENTIONS — SYSTEM SECURE
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-[11px]">
              <thead>
                <tr className="border-b border-white/10 text-[10px] font-mono text-slate-500 uppercase tracking-wider">
                  <th className="pb-3 pl-3 font-normal">Timestamp</th>
                  <th className="pb-3 font-normal">IP</th>
                  <th className="pb-3 font-normal">Threat</th>
                  <th className="pb-3 font-normal">Confidence</th>
                  <th className="pb-3 font-normal hidden md:table-cell">Abuse Score</th>
                  <th className="pb-3 font-normal hidden lg:table-cell">Decision Factors</th>
                  <th className="pb-3 pr-3 font-normal text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                <AnimatePresence initial={false}>
                  {pending.map((entry) => (
                    <motion.tr
                      key={entry.id}
                      initial={{ opacity: 0, y: -6 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, x: 12 }}
                      className="border-b border-white/5 hover:bg-white/5 group"
                    >
                      <td className="py-3 pl-3 font-mono text-slate-400 text-[10px]">
                        {fmtTime(entry.timestamp)}
                      </td>
                      <td className="py-3 font-mono text-white bg-black/40 inline-block px-2 my-1 border border-white/10">
                        {entry.ip}
                      </td>
                      <td className="py-3">
                        <span className="text-[10px] font-bold font-mono px-1.5 py-0.5 border border-malicious/40 bg-malicious/10 text-malicious">
                          {entry.threat_label ?? '—'}
                        </span>
                      </td>
                      <td className="py-3 font-mono">
                        {typeof entry.confidence === 'number'
                          ? `${(entry.confidence * 100).toFixed(1)}%`
                          : '—'}
                      </td>
                      <td className="py-3 font-mono text-slate-400 hidden md:table-cell">
                        {abuseScore(entry)}
                      </td>
                      <td className="py-3 hidden lg:table-cell max-w-sm">
                        <ul className="text-[10px] text-slate-400 space-y-0.5">
                          {(entry.reasoning?.factors ?? []).slice(0, 3).map((f, i) => (
                            <li key={i} className="truncate" title={f}>
                              · {f}
                            </li>
                          ))}
                        </ul>
                      </td>
                      <td className="py-3 pr-3 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => onAllow(entry.ip)}
                            className="flex items-center gap-1 text-[10px] font-bold font-mono uppercase tracking-widest px-2 py-1 border border-benign/40 text-benign hover:bg-benign/10 active:scale-95"
                          >
                            <Check size={10} /> Allow
                          </button>
                          <button
                            onClick={() => onDeny(entry.ip)}
                            className="flex items-center gap-1 text-[10px] font-bold font-mono uppercase tracking-widest px-2 py-1 border border-malicious/40 text-malicious hover:bg-malicious/10 active:scale-95"
                          >
                            <Ban size={10} /> Deny
                          </button>
                        </div>
                      </td>
                    </motion.tr>
                  ))}
                </AnimatePresence>
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Section 2: Active Blocks */}
      <section className="hud-card border-malicious/20 relative overflow-hidden">
        <div className="flex items-center justify-between mb-6 border-b border-white/5 pb-4">
          <h2 className="text-sm font-black text-white uppercase tracking-widest flex items-center gap-2">
            <Shield className="text-malicious" size={16} />
            Section 2 — Active Blocks
          </h2>
          <span className="text-[10px] font-mono text-malicious/60 uppercase">
            {blocked.length} ENFORCED
          </span>
        </div>
        {blocked.length === 0 ? (
          <div className="text-center py-12 border border-dashed border-white/10 opacity-40 italic text-[11px] font-mono uppercase tracking-widest">
            No active blocks in the firewall.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-[11px]">
              <thead>
                <tr className="border-b border-white/10 text-[10px] font-mono text-slate-500 uppercase tracking-wider">
                  <th className="pb-3 pl-3 font-normal">IP</th>
                  <th className="pb-3 font-normal">Blocked At</th>
                  <th className="pb-3 font-normal hidden md:table-cell">Duration</th>
                  <th className="pb-3 font-normal hidden md:table-cell">Expires</th>
                  <th className="pb-3 font-normal">Severity</th>
                  <th className="pb-3 font-normal hidden lg:table-cell">Reason</th>
                  <th className="pb-3 pr-3 font-normal text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                <AnimatePresence initial={false}>
                  {blocked.map((rec) => (
                    <motion.tr
                      key={rec.ip}
                      initial={{ opacity: 0, y: -6 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, x: 12 }}
                      className="border-b border-white/5 hover:bg-white/5 group"
                    >
                      <td className="py-3 pl-3">
                        <span className="font-mono text-white bg-black/40 px-2 py-0.5 border border-malicious/30">
                          {rec.ip}
                        </span>
                      </td>
                      <td className="py-3 font-mono text-slate-400 text-[10px]">
                        {fmtTime(rec.blocked_at)}
                      </td>
                      <td className="py-3 font-mono hidden md:table-cell">{rec.duration ?? '—'}</td>
                      <td className="py-3 font-mono text-slate-400 hidden md:table-cell text-[10px]">
                        {rec.expires_at ? fmtTime(rec.expires_at) : 'permanent'}
                      </td>
                      <td className="py-3">
                        <span className="text-[10px] font-bold font-mono uppercase px-1.5 py-0.5 border border-malicious/40 text-malicious">
                          {rec.severity ?? 'high'}
                        </span>
                      </td>
                      <td className="py-3 text-slate-400 text-[10px] hidden lg:table-cell max-w-sm truncate" title={rec.reason}>
                        {rec.reason ?? '—'}
                      </td>
                      <td className="py-3 pr-3 text-right">
                        <button
                          onClick={() => onUnblock(rec.ip)}
                          className="flex items-center gap-1 text-[10px] font-bold font-mono uppercase tracking-widest px-2 py-1 border border-white/20 text-slate-300 hover:border-primary/40 hover:text-primary active:scale-95 ml-auto"
                        >
                          <Trash2 size={10} /> Unblock
                        </button>
                      </td>
                    </motion.tr>
                  ))}
                </AnimatePresence>
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Toast tray */}
      <div className="fixed bottom-6 right-6 flex flex-col gap-2 z-50">
        <AnimatePresence>
          {toasts.map((t) => (
            <motion.div
              key={t.id}
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              className={`text-[11px] font-mono uppercase tracking-widest px-3 py-2 border ${
                t.tone === 'success'
                  ? 'border-benign/40 bg-benign/10 text-benign'
                  : 'border-malicious/40 bg-malicious/10 text-malicious'
              }`}
            >
              {t.message}
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </div>
  );
}
