import { useState, useEffect } from 'react';
import { ShieldCheck, Clock, ArrowRight } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { idsApi } from '../utils/api';

interface RemediationLog {
  id: string;
  action: string;
  target: string;
  reason: string;
  status: string;
  timestamp: string;
}

export default function RemediationPanel() {
  const [logs, setLogs] = useState<RemediationLog[]>([]);

  useEffect(() => {
    const fetchLogs = async () => {
      try {
        const res = await idsApi.getRemediationLogs();
        setLogs(res.data.slice(0, 5)); // Only show last 5
      } catch (error) {
        console.error("Failed to fetch remediation logs:", error);
      }
    };
    fetchLogs();
    const interval = setInterval(fetchLogs, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="hud-card border-accent-green/20 relative group overflow-hidden">
      <div className="flex items-center justify-between mb-8 border-b border-white/5 pb-4">
        <h3 className="text-xs font-black text-white uppercase tracking-widest flex items-center gap-2">
            <ShieldCheck className="text-benign" size={14} />
            Active Enforcement
        </h3>
        <span className="text-[10px] font-mono text-benign/60 uppercase animate-pulse">
            [Intercept_Active]
        </span>
      </div>

      <div className="space-y-4">
        <AnimatePresence initial={false}>
          {logs.length > 0 ? (
            logs.map((log) => (
              <motion.div
                key={log.id}
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, scale: 0.95 }}
                className="border-l-2 border-benign/30 bg-white/5 p-3 hover:bg-white/10 transition-colors"
              >
                <div className="flex justify-between items-start mb-2">
                  <span className="text-[10px] font-mono font-bold text-benign">
                    {log.action}
                  </span>
                  <div className="flex items-center gap-2 text-slate-600">
                    <Clock size={10} />
                    <span className="text-[9px] font-mono">
                      {new Date(log.timestamp).toLocaleTimeString([], { hour12: false, minute: '2-digit', second: '2-digit' })}
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                    <div className="px-2 py-0.5 bg-slate-900 border border-white/10 text-white font-mono text-[10px]">
                        {log.target}
                    </div>
                    <ArrowRight size={10} className="text-slate-700" />
                    <span className="text-[10px] text-slate-400 truncate max-w-[150px]">
                        {log.reason}
                    </span>
                </div>
              </motion.div>
            ))
          ) : (
            <div className="py-12 text-center border border-dashed border-white/5 opacity-20">
                <p className="text-[10px] italic font-mono uppercase tracking-widest">Awaiting Policy Trigger...</p>
            </div>
          )}
        </AnimatePresence>
      </div>

      {/* Background HUD Decor */}
      <div className="absolute -bottom-4 -right-4 w-24 h-24 border-r border-b border-benign/10 pointer-events-none" />
    </div>
  );
}
