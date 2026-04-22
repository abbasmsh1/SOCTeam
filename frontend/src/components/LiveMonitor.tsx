import { useState, useEffect, useRef, useCallback } from 'react';
import { Activity, BotMessageSquare, Wifi } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { Panel } from './ui/Panel';
import { idsApi } from '../utils/api';

interface Flow {
  id: string;
  SourceIP?: string;
  DestinationIP?: string;
  ['Source IP']?: string;
  ['Destination IP']?: string;
  IPV4_SRC_ADDR?: string;
  IPV4_DST_ADDR?: string;
  Protocol: string;
  Attack?: string;
  timestamp: string;
  severity?: string;
  /** optional — backend may attach confidence for enrichment */
  confidence?: number;
}

function displayEndpoint(flow: Flow, kind: 'src' | 'dst'): string {
  const get = (s: string | undefined) => (s && s.trim() !== '' ? s.trim() : undefined);
  if (kind === 'src') {
    return (
      get(flow.SourceIP) ??
      get(flow['Source IP']) ??
      get(flow.IPV4_SRC_ADDR) ??
      '—'
    );
  }
  return (
    get(flow.DestinationIP) ??
    get(flow['Destination IP']) ??
    get(flow.IPV4_DST_ADDR) ??
    '—'
  );
}

const PROCESSED_CACHE_SIZE = 200;

/**
 * LiveMonitor
 * -----------
 * Real-time flow feed. Radar dish at top-right sweeps continuously, pulsing
 * on new malicious flows. Scanline overlay reinforces the surveillance feel.
 * Also fires /soc/auto-rules in the background for each new malicious flow.
 */
export default function LiveMonitor() {
  const [flows, setFlows] = useState<Flow[]>([]);
  const [autoRulesCount, setAutoRulesCount] = useState(0);
  const [newHitAt, setNewHitAt] = useState<number>(0);

  const processedIds = useRef<Set<string>>(new Set());

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
        setFlows(raw.slice(0, 10));

        for (const flow of raw) {
          const isMalicious =
            flow.Attack &&
            flow.Attack.toLowerCase() !== 'benign' &&
            flow.Attack.toLowerCase() !== 'normal';
          if (isMalicious && !processedIds.current.has(flow.id)) {
            processedIds.current.add(flow.id);
            setNewHitAt(Date.now());
            if (processedIds.current.size > PROCESSED_CACHE_SIZE) {
              const oldest = [...processedIds.current].slice(
                0,
                processedIds.current.size - PROCESSED_CACHE_SIZE,
              );
              oldest.forEach((id) => processedIds.current.delete(id));
            }
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
    <Panel
      className="relative"
      label="Live Ingress Telemetry"
      icon={<Activity className="text-primary animate-pulse" size={14} />}
      meta={
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1 text-benign">
            <Wifi size={10} /> LINK·01
          </span>
          {autoRulesCount > 0 && (
            <span
              className="flex items-center gap-1 text-primary border border-primary/30 bg-primary/5 px-1.5 py-0.5"
              title="Autonomous SOC rule sets generated this session"
            >
              <BotMessageSquare size={10} />
              AUTO-SOC {autoRulesCount}
            </span>
          )}
        </div>
      }
    >
      <div className="scanlines" aria-hidden />

      {/* Radar dish — top right */}
      <div className="absolute top-4 right-4 opacity-80 pointer-events-none">
        <div className="radar">
          <div className="radar__sweep" />
          <div className="radar__dot" />
        </div>
        <div className="mt-1 label text-center text-fog">
          {newHitAt && Date.now() - newHitAt < 1500 ? (
            <span className="text-malicious glow-arterial">CONTACT</span>
          ) : (
            <span>SCANNING</span>
          )}
        </div>
      </div>

      <div className="overflow-x-auto relative">
        <table className="w-full text-left num text-[11px]">
          <thead>
            <tr className="text-fog/70 border-b border-paper/5">
              <th className="label pb-3 pr-3 w-8">#</th>
              <th className="label pb-3 pr-3">SOURCE</th>
              <th className="label pb-3 pr-3">DESTINATION</th>
              <th className="label pb-3 pr-3">PROTO</th>
              <th className="label pb-3 pr-3 text-right">VECTOR</th>
              <th className="label pb-3 w-12 text-right">·</th>
            </tr>
          </thead>
          <tbody>
            <AnimatePresence initial={false}>
              {flows.map((flow, idx) => {
                const attack = (flow.Attack ?? 'Benign').toString();
                const isBenign = attack.toLowerCase() === 'benign';
                return (
                  <motion.tr
                    key={flow.id}
                    layout
                    initial={{ opacity: 0, x: -10, backgroundColor: 'rgba(249,115,22,0.15)' }}
                    animate={{ opacity: 1, x: 0, backgroundColor: 'rgba(0,0,0,0)' }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 0.45, backgroundColor: { duration: 1.1 } }}
                    className="group border-b border-paper/5 last:border-0 hover:bg-paper/[0.03]"
                  >
                    <td className="py-2.5 pr-3 text-fog/60">{String(idx + 1).padStart(2, '0')}</td>
                    <td className="py-2.5 pr-3 text-paper font-semibold">
                      {displayEndpoint(flow, 'src')}
                    </td>
                    <td className="py-2.5 pr-3 text-fog">
                      {displayEndpoint(flow, 'dst')}
                    </td>
                    <td className="py-2.5 pr-3 text-paper/70">
                      <span className="border border-paper/10 px-1.5 py-0.5 text-[10px]">
                        {flow.Protocol ?? 'N/A'}
                      </span>
                    </td>
                    <td className="py-2.5 pr-3 text-right">
                      <span
                        className={`px-1.5 py-0.5 font-bold text-[10px] uppercase ${
                          isBenign
                            ? 'text-benign/60 border border-benign/20'
                            : 'text-malicious bg-malicious/10 border border-malicious/40 glow-arterial'
                        }`}
                      >
                        {attack}
                      </span>
                    </td>
                    <td className="py-2.5 text-right">
                      {!isBenign && (
                        <span className="inline-block w-1.5 h-1.5 bg-malicious animate-pulse" />
                      )}
                    </td>
                  </motion.tr>
                );
              })}
            </AnimatePresence>
          </tbody>
        </table>
      </div>

      {flows.length === 0 && (
        <div className="py-20 text-center label text-fog/30 tracking-[0.3em] animate-pulse">
          establishing link to sensor array…
        </div>
      )}
    </Panel>
  );
}
