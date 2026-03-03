import { useState, useEffect } from 'react';
import { Activity, AlertCircle, CheckCircle } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import type { LiveFlow } from '../types';
import { idsApi } from '../utils/api';

export default function LiveMonitor() {
  const [flows, setFlows] = useState<LiveFlow[]>([]);

  useEffect(() => {
    const fetchEvents = async () => {
      try {
        const response = await idsApi.getEvents();
        setFlows(response.data);
      } catch (error) {
        console.error('Failed to fetch events:', error);
      }
    };

    fetchEvents();
    const interval = setInterval(fetchEvents, 3000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="glass rounded-2xl overflow-hidden mt-6">
      <div className="p-6 border-b border-white/5 flex items-center justify-between">
        <h3 className="text-lg font-bold text-white flex items-center gap-2">
          <Activity className="text-primary w-5 h-5" />
          Live Traffic Monitor
        </h3>
        <div className="flex gap-2">
          <span className="px-3 py-1 bg-primary/10 text-primary text-[10px] font-bold rounded-full">LIVE PREVIEW</span>
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-white/5">
              <th className="p-4 text-xs font-bold text-slate-500 uppercase">Timestamp</th>
              <th className="p-4 text-xs font-bold text-slate-500 uppercase">Source</th>
              <th className="p-4 text-xs font-bold text-slate-500 uppercase">Destination</th>
              <th className="p-4 text-xs font-bold text-slate-500 uppercase">Attack Type</th>
              <th className="p-4 text-xs font-bold text-slate-500 uppercase">Confidence</th>
              <th className="p-4 text-xs font-bold text-slate-500 uppercase text-center">Status</th>
            </tr>
          </thead>
          <tbody>
            <AnimatePresence mode='popLayout'>
              {flows.map((flow, i) => (
                <motion.tr 
                  key={i}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0 }}
                  className="border-b border-white/5 hover:bg-white/5 transition-colors group"
                >
                  <td className="p-4 text-xs text-slate-400 font-mono">
                    {new Date(flow.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="p-4">
                    <div className="text-xs font-medium text-white">{flow.SourceIP}</div>
                    <div className="text-[10px] text-slate-500">Port: {flow.SourcePort}</div>
                  </td>
                  <td className="p-4">
                    <div className="text-xs font-medium text-white">{flow.DestinationIP}</div>
                    <div className="text-[10px] text-slate-500">Port: {flow.DestinationPort}</div>
                  </td>
                  <td className="p-4">
                    <span className={`text-[10px] font-bold px-2 py-1 rounded-md ${flow.Attack === 'BENIGN' ? 'bg-benign/10 text-benign' : 'bg-malicious/10 text-malicious'}`}>
                      {flow.Attack}
                    </span>
                  </td>
                  <td className="p-4">
                    <div className="w-16 bg-white/5 h-1.5 rounded-full overflow-hidden">
                      <div 
                        className={`h-full ${flow.confidence > 0.9 ? (flow.Attack === 'BENIGN' ? 'bg-benign' : 'bg-malicious') : 'bg-warning'}`} 
                        style={{ width: `${flow.confidence * 100}%` }} 
                      />
                    </div>
                    <div className="text-[10px] text-slate-500 mt-1">{(flow.confidence * 100).toFixed(1)}%</div>
                  </td>
                  <td className="p-4 text-center">
                    {flow.Attack === 'BENIGN' ? (
                      <CheckCircle className="w-4 h-4 text-benign mx-auto" />
                    ) : (
                      <AlertCircle className="w-4 h-4 text-malicious mx-auto animate-pulse" />
                    )}
                  </td>
                </motion.tr>
              ))}
            </AnimatePresence>
          </tbody>
        </table>
      </div>
    </div>
  );
}
