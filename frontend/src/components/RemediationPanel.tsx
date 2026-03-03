import React, { useState, useEffect } from 'react';
import { ShieldAlert, CheckCircle, Clock, Trash2, ExternalLink } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { idsApi } from '../utils/api';

interface RemediationLog {
  timestamp: string;
  threat: any;
  planned_defense: string;
  enforced_rules: any[];
  status: string;
  dry_run: boolean;
}

export default function RemediationPanel() {
  const [logs, setLogs] = useState<RemediationLog[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchLogs = async () => {
    try {
      const response = await idsApi.getRemediationLogs();
      setLogs(response.data);
    } catch (error) {
      console.error("Failed to fetch remediation logs:", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
    const interval = setInterval(fetchLogs, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="glass rounded-2xl p-6 h-full">
      <div className="flex items-center justify-between mb-6">
        <h3 className="text-lg font-bold text-white flex items-center gap-2">
          <ShieldAlert className="text-malicious" size={20} />
          Active Enforcement
        </h3>
        <span className="text-[10px] bg-white/5 px-2 py-1 rounded text-slate-400 font-mono uppercase tracking-widest">
          Automated Response
        </span>
      </div>

      <div className="space-y-4 max-h-[400px] overflow-y-auto pr-2 custom-scrollbar">
        <AnimatePresence mode="popLayout">
          {logs.length > 0 ? (
            logs.map((log, idx) => (
              <motion.div
                key={`${log.timestamp}-${idx}`}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, scale: 0.95 }}
                className="p-4 rounded-xl bg-white/5 border border-white/5 hover:border-white/10 transition-all group"
              >
                <div className="flex justify-between items-start mb-2">
                  <div className="flex items-center gap-2">
                    <div className={`w-2 h-2 rounded-full ${log.status === 'ERROR' ? 'bg-malicious' : 'bg-benign'}`} />
                    <span className="text-xs font-bold text-white">
                      {log.threat.Attack || 'Defensive Action'}
                    </span>
                  </div>
                  <span className="text-[10px] text-slate-500 font-medium flex items-center gap-1">
                    <Clock size={10} />
                    {new Date(log.timestamp).toLocaleTimeString()}
                  </span>
                </div>

                <div className="space-y-2">
                  {log.enforced_rules && log.enforced_rules.length > 0 ? (
                    log.enforced_rules.map((rule, ruleIdx) => (
                      <div key={ruleIdx} className="flex items-center justify-between bg-black/20 p-2 rounded-lg text-[11px]">
                        <div className="flex items-center gap-2">
                          <code className="text-primary font-bold">{rule.action}</code>
                          <span className="text-slate-300 font-mono">{rule.target}</span>
                        </div>
                        <CheckCircle size={12} className="text-benign opacity-50" />
                      </div>
                    ))
                  ) : (
                    <p className="text-[11px] text-slate-500 italic px-2">
                      Monitoring deployment...
                    </p>
                  )}
                </div>

                {log.dry_run && (
                  <div className="mt-3 pt-2 border-t border-white/5 flex justify-between items-center">
                    <span className="text-[9px] text-slate-500 uppercase tracking-wider font-bold">Simulation Mode</span>
                    <button className="text-[9px] text-primary hover:underline flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                      View Source <ExternalLink size={8} />
                    </button>
                  </div>
                )}
              </motion.div>
            ))
          ) : (
            <div className="text-center py-12 text-slate-500">
              <Clock className="mx-auto mb-2 opacity-20" size={32} />
              <p className="text-xs italic">No active blocks enforced.</p>
            </div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
