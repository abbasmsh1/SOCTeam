import { useState, useEffect } from 'react';
import { ShieldCheck, Clock, ArrowRight } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { Panel } from './ui/Panel';
import { idsApi } from '../utils/api';

interface RemediationLog {
  id?: string;
  action?: string;
  target?: string;
  reason?: string;
  status?: string;
  timestamp?: string;
}

export default function RemediationPanel() {
  const [logs, setLogs] = useState<RemediationLog[]>([]);

  useEffect(() => {
    const fetchLogs = async () => {
      try {
        const res = await idsApi.getRemediationLogs();
        const raw = Array.isArray(res.data) ? res.data : [];
        setLogs(raw.slice(0, 5));
      } catch (error) {
        console.error('Failed to fetch remediation logs:', error);
      }
    };
    fetchLogs();
    const interval = setInterval(fetchLogs, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <Panel
      accent="phosphor"
      label="Active Enforcement"
      icon={<ShieldCheck size={14} className="text-benign" />}
      meta={<span className="text-benign animate-pulse glow-phosphor">[ intercept // active ]</span>}
    >
      <div className="space-y-3">
        <AnimatePresence initial={false}>
          {logs.length > 0 ? (
            logs.map((log) => (
              <motion.article
                key={log.id ?? `${log.timestamp ?? 'x'}-${log.action ?? 'a'}`}
                layout
                initial={{ opacity: 0, x: 16 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, scale: 0.96 }}
                className="border-l-2 border-benign/40 bg-paper/[0.02] hover:bg-paper/[0.04] p-3 transition-colors"
              >
                <div className="flex justify-between items-start mb-2">
                  <span className="num text-[11px] font-bold text-benign glow-phosphor">
                    {log.action ?? 'NO_ACTION'}
                  </span>
                  <div className="flex items-center gap-1.5 text-fog">
                    <Clock size={10} />
                    <span className="num text-[10px]">
                      {log.timestamp
                        ? new Date(log.timestamp).toLocaleTimeString([], {
                            hour12: false,
                            minute: '2-digit',
                            second: '2-digit',
                          })
                        : '--:--'}
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-2.5 flex-wrap">
                  <span className="num text-paper bg-graphite border border-paper/10 px-2 py-0.5 text-[11px]">
                    {log.target ?? 'unknown'}
                  </span>
                  <ArrowRight size={11} className="text-fog/50" />
                  <span className="stamp text-paper/70 text-[13px] leading-snug truncate max-w-[220px]">
                    {log.reason ?? 'no reason provided'}
                  </span>
                </div>
              </motion.article>
            ))
          ) : (
            <div className="py-10 text-center border border-dashed border-paper/5">
              <p className="label text-fog/40 tracking-[0.3em]">awaiting policy trigger…</p>
            </div>
          )}
        </AnimatePresence>
      </div>
    </Panel>
  );
}
