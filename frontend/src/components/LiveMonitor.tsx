/**
 * LiveMonitor.tsx
 * ===============
 * Displays the most recent ingress flows from the IDS event stream.
 * Polls GET /events every second for live telemetry.
 *
 * Auto-SOC Integration:
 *   Whenever a new *malicious* flow appears that hasn't been seen before,
 *   POST /soc/auto-rules is fired in the background so the
 *   DefensiveActionSandbox is updated automatically. The SandboxStatePanel
 *   will pick up the resulting state on its next 5 s poll.
 */

import { useState, useEffect, useRef, useCallback } from 'react';
import { Activity, Wifi, HardDrive, BotMessageSquare } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { idsApi } from '../utils/api';

interface Flow {
  id: string;
  SourceIP: string;
  DestinationIP: string;
  Protocol: string;
  Attack?: string;
  timestamp: string;
  severity?: string;
}

/** How many recently-processed flow IDs to remember (prevent duplicate rule generation). */
const PROCESSED_CACHE_SIZE = 200;

export default function LiveMonitor() {
  const [flows, setFlows] = useState<Flow[]>([]);
  /** Running count of autonomous rule-generation calls fired this session. */
  const [autoRulesCount, setAutoRulesCount] = useState(0);

  /**
   * Cache of flow IDs for which we've already triggered auto-rule generation.
   * Stored in a ref so it doesn't cause re-renders and survives poll cycles.
   */
  const processedIds = useRef<Set<string>>(new Set());

  /**
   * Fire-and-forget: ask the SOC engine to generate defensive rules for a
   * malicious flow. Does not throw — failures are logged silently so the
   * monitor table remains stable.
   */
  const triggerAutoRules = useCallback(async (flow: Flow) => {
    try {
      await idsApi.generateAutoRules({
        detection: {
          SourceIP:      flow.SourceIP,
          DestinationIP: flow.DestinationIP,
          Protocol:      flow.Protocol,
          Attack:        flow.Attack,
          timestamp:     flow.timestamp,
          severity:      flow.severity ?? 'HIGH',
        },
      });
      setAutoRulesCount((n) => n + 1);
    } catch (err) {
      console.warn('[LiveMonitor] Auto-rules generation failed for flow', flow.id, err);
    }
  }, []);

  useEffect(() => {
    const fetchFlows = async () => {
      try {
        const res = await idsApi.getEvents();
        const raw: Flow[] = Array.isArray(res.data) ? res.data : [];
        setFlows(raw.slice(0, 8)); // Top 8 most recent flows in the table

        // ── Auto-SOC: process any new malicious flows ──────────────────────
        for (const flow of raw) {
          const isMalicious =
            flow.Attack &&
            flow.Attack.toLowerCase() !== 'benign' &&
            flow.Attack.toLowerCase() !== 'normal';

          if (isMalicious && !processedIds.current.has(flow.id)) {
            processedIds.current.add(flow.id);

            // Trim the cache if it grows too large
            if (processedIds.current.size > PROCESSED_CACHE_SIZE) {
              const oldest = [...processedIds.current].slice(
                0,
                processedIds.current.size - PROCESSED_CACHE_SIZE
              );
              oldest.forEach((id) => processedIds.current.delete(id));
            }

            // Fire in background — don't await to keep the poll fast
            triggerAutoRules(flow);
          }
        }
      } catch (error) {
        console.error('[LiveMonitor] Failed to fetch flows:', error);
      }
    };

    fetchFlows();
    const interval = setInterval(fetchFlows, 1000);
    return () => clearInterval(interval);
  }, [triggerAutoRules]);

  return (
    <div className="hud-card border-white/5 relative bg-black/60">
      {/* Header */}
      <div className="flex items-center justify-between mb-8 border-b border-white/5 pb-4">
        <h3 className="text-xs font-black text-white uppercase tracking-widest flex items-center gap-2">
          <Activity className="text-primary animate-pulse" size={14} />
          Live Ingress Telemetry
        </h3>
        <div className="flex gap-4 items-center">
          <div className="flex items-center gap-2 opacity-50">
            <Wifi size={10} className="text-benign" />
            <span className="text-[8px] font-mono tracking-tighter uppercase">Link 01: UP</span>
          </div>
          <div className="flex items-center gap-2 opacity-50 text-slate-500">
            <HardDrive size={10} />
            <span className="text-[8px] font-mono tracking-tighter uppercase">Buffer: 4.2%</span>
          </div>
          {/* Auto-SOC rule counter badge */}
          {autoRulesCount > 0 && (
            <div
              className="flex items-center gap-1 text-[9px] font-mono text-primary border border-primary/30 bg-primary/5 px-2 py-0.5"
              title="Number of autonomous SOC rule sets generated this session"
            >
              <BotMessageSquare size={10} />
              <span>AUTO-SOC: {autoRulesCount}</span>
            </div>
          )}
        </div>
      </div>

      {/* Flow table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left font-mono text-[10px]">
          <thead>
            <tr className="text-slate-600 border-b border-white/5 uppercase tracking-tighter">
              <th className="pb-3 px-2">SOURCE_ADDR</th>
              <th className="pb-3 px-2">DEST_ADDR</th>
              <th className="pb-3 px-2">PROTO</th>
              <th className="pb-3 px-2 text-right">VECTOR_MATCH</th>
            </tr>
          </thead>
          <tbody>
            <AnimatePresence initial={false}>
              {flows.map((flow) => {
                const attack = (flow.Attack ?? 'Benign').toString();
                const isBenign = attack.toLowerCase() === 'benign';
                return (
                  <motion.tr
                    key={flow.id}
                    initial={{ opacity: 0, backgroundColor: 'rgba(255,255,255,0.05)' }}
                    animate={{ opacity: 1, backgroundColor: 'rgba(255,255,255,0)' }}
                    className="group hover:bg-white/5 transition-colors border-b border-white/5 last:border-0"
                  >
                    <td className="py-3 px-2 text-slate-300 group-hover:text-white">
                      {flow.SourceIP ?? 'Unknown'}
                    </td>
                    <td className="py-3 px-2 text-slate-500">{flow.DestinationIP ?? 'Unknown'}</td>
                    <td className="py-3 px-2 font-bold text-slate-400 opacity-50">
                      {flow.Protocol ?? 'N/A'}
                    </td>
                    <td className="py-3 px-2 text-right">
                      <span
                        className={`px-1 font-bold ${
                          isBenign ? 'text-benign/40' : 'text-malicious bg-malicious/10'
                        }`}
                      >
                        {attack.toUpperCase()}
                      </span>
                    </td>
                  </motion.tr>
                );
              })}
            </AnimatePresence>
          </tbody>
        </table>
      </div>

      {flows.length === 0 && (
        <div className="py-20 text-center opacity-10 font-mono text-[9px] uppercase tracking-[0.2em] animate-pulse">
          Establishing Link to Sensor Array...
        </div>
      )}
    </div>
  );
}
