/**
 * RLStatsPanel.tsx
 * Live view of the RL feedback pipeline:
 *   - experience buffer size (pending / labeled / trained)
 *   - mean reward across labeled rows
 *   - per-class FP rates + adaptive thresholds
 *
 * Polls GET /rl/stats every 10s. No-ops if RL is disabled server-side.
 */

import { useEffect, useState } from 'react';
import { Brain, TrendingUp, AlertCircle, Cpu } from 'lucide-react';
import { idsApi } from '../utils/api';

interface RLStats {
  enabled?: boolean;
  total?: number;
  by_status?: Record<string, number>;
  avg_reward?: number;
  per_class?: Record<string, { n: number; avg_conf: number }>;
  fp_rate_by_class?: Record<string, number>;
  latest_ts?: string | null;
  policy?: {
    base_threshold: number;
    thresholds: Record<string, number>;
    fp_rates: Record<string, number>;
    sample_counts: Record<string, number>;
  };
}

const POLL_MS = 10_000;

export default function RLStatsPanel() {
  const [stats, setStats] = useState<RLStats | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [training, setTraining] = useState(false);
  const [trainResult, setTrainResult] = useState<string | null>(null);

  useEffect(() => {
    const fetchOnce = async () => {
      try {
        const res = await idsApi.getRLStats();
        setStats(res.data);
        setError(null);
      } catch (err: any) {
        setError(err?.message ?? 'Failed to fetch RL stats');
      }
    };
    fetchOnce();
    const t = setInterval(fetchOnce, POLL_MS);
    return () => clearInterval(t);
  }, []);

  const onTrain = async () => {
    setTraining(true);
    setTrainResult(null);
    try {
      const res = await idsApi.triggerRLTrain();
      const r = res.data.result ?? {};
      setTrainResult(`${r.status ?? 'done'} — rows=${r.rows_used ?? '?'}`);
    } catch (err: any) {
      setTrainResult(`fail: ${err?.message ?? 'error'}`);
    } finally {
      setTraining(false);
    }
  };

  if (!stats) {
    return (
      <div className="hud-card border-primary/20">
        <h3 className="text-xs font-black text-white uppercase tracking-widest flex items-center gap-2">
          <Brain size={14} className="text-primary" />
          RL Feedback Pipeline
        </h3>
        <p className="text-[10px] font-mono text-slate-500 mt-4">
          {error ?? 'Loading RL stats…'}
        </p>
      </div>
    );
  }

  if (stats.enabled === false) {
    return (
      <div className="hud-card border-slate-700">
        <h3 className="text-xs font-black text-white uppercase tracking-widest flex items-center gap-2">
          <Brain size={14} className="text-slate-500" />
          RL Feedback Pipeline — DISABLED
        </h3>
        <p className="text-[10px] font-mono text-slate-500 mt-4">
          Set <code className="text-primary">IDS_RL_ENABLED=true</code> to enable.
        </p>
      </div>
    );
  }

  const total = stats.total ?? 0;
  const labeled = stats.by_status?.labeled ?? 0;
  const pending = stats.by_status?.pending ?? 0;
  const trained = stats.by_status?.trained ?? 0;
  const avgReward = stats.avg_reward ?? 0;
  const rewardColor = avgReward > 0.3 ? 'text-benign' : avgReward < -0.3 ? 'text-malicious' : 'text-warning';

  const fpRates = Object.entries(stats.fp_rate_by_class ?? {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6);

  return (
    <div className="hud-card border-primary/20 relative overflow-hidden">
      <div className="flex items-center justify-between mb-6 border-b border-white/5 pb-4">
        <h3 className="text-sm font-black text-white uppercase tracking-widest flex items-center gap-2">
          <Brain size={16} className="text-primary" />
          RL Feedback Pipeline
        </h3>
        <button
          onClick={onTrain}
          disabled={training || labeled < 32}
          className={`
            flex items-center gap-1.5 text-[10px] font-bold font-mono uppercase tracking-widest
            px-3 py-1.5 border transition-all
            ${labeled < 32
              ? 'text-slate-700 border-slate-800 cursor-not-allowed'
              : training
              ? 'text-warning border-warning/40 cursor-wait'
              : 'text-primary border-primary/40 hover:bg-primary/10 active:scale-95 cursor-pointer'}
          `}
        >
          <Cpu size={10} />
          {training ? 'Training…' : labeled < 32 ? `Need ${32 - labeled} labels` : 'Trigger Training'}
        </button>
      </div>

      <div className="grid grid-cols-4 gap-3 mb-5">
        <Metric label="Total" value={total} accent="primary" />
        <Metric label="Pending" value={pending} accent="warning" />
        <Metric label="Labeled" value={labeled} accent="benign" />
        <Metric label="Trained" value={trained} accent="primary" />
      </div>

      <div className="flex items-center gap-3 mb-5 border border-white/5 bg-black/40 px-3 py-2">
        <TrendingUp size={12} className={rewardColor} />
        <span className="text-[10px] font-mono text-slate-500 uppercase">Mean Reward</span>
        <span className={`text-xl font-black font-mono ml-auto ${rewardColor}`}>{avgReward.toFixed(3)}</span>
      </div>

      {fpRates.length > 0 && (
        <div>
          <p className="text-[9px] font-bold font-mono uppercase tracking-widest text-slate-500 mb-2">
            ── Top False-Positive Classes (drives adaptive threshold)
          </p>
          <ul className="space-y-1.5">
            {fpRates.map(([cls, rate]) => {
              const threshold = stats.policy?.thresholds?.[cls.toUpperCase()] ?? stats.policy?.base_threshold ?? 0.85;
              const bumped = threshold > (stats.policy?.base_threshold ?? 0.85) + 0.001;
              return (
                <li key={cls} className="flex items-center gap-2 text-[10px] font-mono">
                  <span className="text-slate-300 w-28 truncate">{cls}</span>
                  <div className="flex-1 h-1 bg-white/5 relative">
                    <div
                      className={`absolute top-0 left-0 h-full ${rate > 0.5 ? 'bg-malicious' : rate > 0.2 ? 'bg-warning' : 'bg-benign'}`}
                      style={{ width: `${Math.min(100, rate * 100)}%` }}
                    />
                  </div>
                  <span className="text-slate-400 w-14 text-right">{(rate * 100).toFixed(1)}%</span>
                  <span className={`w-20 text-right ${bumped ? 'text-warning' : 'text-slate-600'}`}>
                    thr {threshold.toFixed(2)}
                  </span>
                </li>
              );
            })}
          </ul>
        </div>
      )}

      {trainResult && (
        <div className="mt-4 text-[10px] font-mono text-primary border-l-2 border-primary/50 pl-2 py-1">
          <AlertCircle size={10} className="inline mr-1" />
          {trainResult} — restart backend to load new checkpoint
        </div>
      )}

      <div className="absolute top-0 left-0 w-2 h-2 border-t border-l border-primary/50" />
      <div className="absolute top-0 right-0 w-2 h-2 border-t border-r border-primary/50" />
      <div className="absolute bottom-0 left-0 w-2 h-2 border-b border-l border-primary/50" />
      <div className="absolute bottom-0 right-0 w-2 h-2 border-b border-r border-primary/50" />
    </div>
  );
}

function Metric({ label, value, accent }: { label: string; value: number; accent: 'primary' | 'warning' | 'benign' | 'malicious' }) {
  const borderClass = {
    primary: 'border-primary/20',
    warning: 'border-warning/20',
    benign: 'border-benign/20',
    malicious: 'border-malicious/20',
  }[accent];
  const textClass = {
    primary: 'text-primary',
    warning: 'text-warning',
    benign: 'text-benign',
    malicious: 'text-malicious',
  }[accent];
  return (
    <div className={`bg-black/40 border ${borderClass} px-3 py-2`}>
      <p className="text-[9px] font-mono text-slate-500 uppercase mb-1">{label}</p>
      <p className={`text-xl font-black font-mono ${textClass}`}>{value}</p>
    </div>
  );
}
