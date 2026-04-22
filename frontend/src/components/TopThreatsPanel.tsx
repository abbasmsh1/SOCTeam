import { useEffect, useState } from 'react';
import { Crosshair, MapPin } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { Panel } from './ui/Panel';
import { idsApi } from '../utils/api';

interface TopThreat {
  ip: string;
  attack: string;
  count: number;
  last_seen?: string;
  confidence?: number;
}

/**
 * TopThreatsPanel
 * ---------------
 * Leaderboard of attacking source IPs, fed by GET /threats/top.
 * Each row is a small reticle with attack type, hit count, and last-seen stamp.
 */
export default function TopThreatsPanel() {
  const [rows, setRows] = useState<TopThreat[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      try {
        const res = await idsApi.getTopThreats(3600, 8);
        if (cancelled) return;
        const list: TopThreat[] = Array.isArray(res.data) ? res.data : res.data?.threats ?? [];
        setRows(list);
        setError(null);
      } catch (err: any) {
        if (!cancelled) setError(err?.message ?? 'Unreachable');
      }
    };
    tick();
    const id = setInterval(tick, 10_000);
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  const max = Math.max(1, ...rows.map((r) => r.count));

  return (
    <Panel
      accent="ember"
      label="Top Threats · 60m"
      icon={<Crosshair size={14} />}
      meta={<span>Source IP Leaderboard</span>}
    >
      {error && rows.length === 0 && (
        <div className="py-10 text-center label text-fog/60">
          <span className="stamp not-italic text-fog/70 block mb-2">[ uplink failure ]</span>
          {error}
        </div>
      )}

      {rows.length === 0 && !error && (
        <div className="py-10 text-center label text-fog/40 tracking-[0.3em]">
          no elevated actors observed
        </div>
      )}

      <ol className="space-y-2">
        <AnimatePresence initial={false}>
          {rows.map((row, idx) => {
            const pct = (row.count / max) * 100;
            const conf = row.confidence != null ? Math.round(row.confidence * 100) : null;
            return (
              <motion.li
                key={row.ip}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0 }}
                transition={{ delay: idx * 0.03 }}
                className="group relative border-l-2 border-primary/20 hover:border-primary pl-3 py-2"
              >
                <div className="flex items-baseline justify-between gap-3">
                  <div className="flex items-baseline gap-3 min-w-0">
                    <span className="num text-fog text-[10px] w-5">#{String(idx + 1).padStart(2, '0')}</span>
                    <span className="num text-paper font-semibold truncate">{row.ip}</span>
                    <span className="label text-malicious hidden sm:inline">{row.attack}</span>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    {conf != null && (
                      <span className="label text-fog">
                        {conf}<span className="opacity-60">%</span>
                      </span>
                    )}
                    <span className="num text-primary text-sm font-bold">
                      {row.count.toLocaleString()}
                    </span>
                  </div>
                </div>

                {/* horizon bar showing relative intensity */}
                <div className="mt-2 h-[2px] bg-paper/5 relative overflow-hidden">
                  <motion.div
                    className="absolute left-0 top-0 h-full bg-primary/80"
                    initial={{ width: 0 }}
                    animate={{ width: `${pct}%` }}
                    transition={{ duration: 0.6, ease: [0.2, 0.9, 0.2, 1] }}
                  />
                </div>

                {row.last_seen && (
                  <div className="mt-1 flex items-center gap-1 label text-fog/50">
                    <MapPin size={8} />
                    {new Date(row.last_seen).toLocaleTimeString([], { hour12: false })}
                  </div>
                )}
              </motion.li>
            );
          })}
        </AnimatePresence>
      </ol>
    </Panel>
  );
}
