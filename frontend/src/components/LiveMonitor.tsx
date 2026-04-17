import { useState, useEffect } from 'react';
import { Activity, Wifi, HardDrive } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { idsApi } from '../utils/api';

interface Flow {
  id: string;
  SourceIP: string;
  DestinationIP: string;
  Protocol: string;
  Attack: string;
  timestamp: string;
  severity?: string;
}

export default function LiveMonitor() {
  const [flows, setFlows] = useState<Flow[]>([]);

  useEffect(() => {
    const fetchFlows = async () => {
      try {
        const res = await idsApi.getEvents();
        setFlows(res.data.slice(0, 8)); // Top 8 flows
      } catch (error) {
        console.error("Failed to fetch flows:", error);
      }
    };
    fetchFlows();
    const interval = setInterval(fetchFlows, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="hud-card border-white/5 relative bg-black/60">
      <div className="flex items-center justify-between mb-8 border-b border-white/5 pb-4">
        <h3 className="text-xs font-black text-white uppercase tracking-widest flex items-center gap-2">
            <Activity className="text-primary animate-pulse" size={14} />
            Live Ingress Telemetry
        </h3>
        <div className="flex gap-4">
             <div className="flex items-center gap-2 opacity-50">
                <Wifi size={10} className="text-benign" />
                <span className="text-[8px] font-mono tracking-tighter uppercase">Link 01: UP</span>
             </div>
             <div className="flex items-center gap-2 opacity-50 text-slate-500">
                <HardDrive size={10} />
                <span className="text-[8px] font-mono tracking-tighter uppercase">Buffer: 4.2%</span>
             </div>
        </div>
      </div>

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
              {flows.map((flow) => (
                <motion.tr
                  key={flow.id}
                  initial={{ opacity: 0, backgroundColor: 'rgba(255,255,255,0.05)' }}
                  animate={{ opacity: 1, backgroundColor: 'rgba(255,255,255,0)' }}
                  className="group hover:bg-white/5 transition-colors border-b border-white/5 last:border-0"
                >
                  <td className="py-3 px-2 text-slate-300 group-hover:text-white">{flow.SourceIP}</td>
                  <td className="py-3 px-2 text-slate-500">{flow.DestinationIP}</td>
                  <td className="py-3 px-2 font-bold text-slate-400 opacity-50">{flow.Protocol}</td>
                  <td className="py-3 px-2 text-right">
                    <span className={`px-1 font-bold ${
                      flow.Attack === 'Benign' ? 'text-benign/40' : 'text-malicious bg-malicious/10'
                    }`}>
                      {flow.Attack.toUpperCase()}
                    </span>
                  </td>
                </motion.tr>
              ))}
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
