import { useState } from 'react';
import { Send, AlertTriangle, CheckCircle2, Loader2 } from 'lucide-react';
import { idsApi } from '../utils/api';

const SAMPLE_DETECTION = {
  "Source IP": "203.0.113.42",
  "Destination IP": "10.0.0.21",
  "Protocol": "TCP",
  "Destination Port": 445,
  "prediction": "SMB-Lateral",
  "confidence": 0.92,
};

interface DispatchResult {
  rules_enforced: Array<{ rule: Record<string, any>; result?: Record<string, any> }>;
  rules_failed: Array<{ rule: Record<string, any>; status?: string; error?: string }>;
  threat_context?: Record<string, any>;
}

export default function DispatchAlert() {
  const [payload, setPayload] = useState(JSON.stringify(SAMPLE_DETECTION, null, 2));
  const [result, setResult] = useState<DispatchResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleDispatch = async () => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const detection = JSON.parse(payload);
      const res = await idsApi.generateAutoRules(detection);
      setResult(res.data);
    } catch (err: any) {
      if (err instanceof SyntaxError) {
        setError(`Invalid JSON: ${err.message}`);
      } else {
        setError(err?.response?.data?.detail ?? err?.message ?? 'Dispatch failed');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="hud-card border-warning/20 relative overflow-hidden">
      <div className="flex items-center justify-between mb-6 border-b border-white/5 pb-4">
        <h3 className="text-sm font-black text-white uppercase tracking-widest flex items-center gap-2">
          <AlertTriangle className="text-warning" size={16} />
          Dispatch Alert &rarr; Auto Rule Generator
        </h3>
        <span className="text-[10px] font-mono text-warning/60 uppercase animate-pulse">
          [HITL_READY]
        </span>
      </div>

      <label className="text-[10px] font-mono text-slate-500 uppercase tracking-widest mb-2 block">
        Detection Payload (JSON)
      </label>
      <textarea
        value={payload}
        onChange={(e) => setPayload(e.target.value)}
        spellCheck={false}
        className="w-full h-40 bg-black/60 border border-white/10 text-[11px] font-mono text-white p-3 focus:border-primary/50 focus:outline-none resize-y"
      />

      <div className="flex items-center justify-between mt-4">
        <span className="text-[10px] font-mono text-slate-500">
          POST /soc/auto-rules
        </span>
        <button
          onClick={handleDispatch}
          disabled={loading}
          className={`
            flex items-center gap-2 text-[11px] font-bold font-mono uppercase tracking-widest
            px-4 py-2 border transition-all
            ${loading
              ? 'text-slate-600 border-slate-800 cursor-not-allowed'
              : 'text-warning border-warning/40 hover:bg-warning/10 active:scale-95 cursor-pointer'}
          `}
        >
          {loading ? <Loader2 size={12} className="animate-spin" /> : <Send size={12} />}
          {loading ? 'Dispatching...' : 'Dispatch Alert'}
        </button>
      </div>

      {error && (
        <div className="mt-4 border border-malicious/40 bg-malicious/10 px-3 py-2 text-[11px] font-mono text-malicious">
          {error}
        </div>
      )}

      {result && (
        <div className="mt-4 space-y-3">
          <div className="flex items-center gap-3 text-[11px] font-mono">
            <span className="flex items-center gap-1 text-benign">
              <CheckCircle2 size={12} /> ENFORCED: {result.rules_enforced?.length ?? 0}
            </span>
            <span className="flex items-center gap-1 text-malicious">
              <AlertTriangle size={12} /> FAILED: {result.rules_failed?.length ?? 0}
            </span>
            {result.threat_context?.attack_type && (
              <span className="text-slate-500 uppercase">
                attack: <span className="text-white">{result.threat_context.attack_type}</span>
              </span>
            )}
          </div>
          {result.rules_enforced?.length > 0 && (
            <ul className="text-[10px] font-mono text-slate-300 space-y-1">
              {result.rules_enforced.map((r, i) => (
                <li key={i} className="border-l-2 border-benign/50 pl-2">
                  {String(r.rule?.action ?? '?')} &rarr; {String(r.rule?.target ?? r.rule?.src_ip ?? '?')}
                  <span className="text-slate-600"> · {r.result?.status ?? 'OK'}</span>
                </li>
              ))}
            </ul>
          )}
          {result.rules_failed?.length > 0 && (
            <ul className="text-[10px] font-mono text-slate-400 space-y-1">
              {result.rules_failed.map((r, i) => (
                <li key={i} className="border-l-2 border-malicious/50 pl-2">
                  {String(r.rule?.action ?? '?')} &rarr; {String(r.rule?.target ?? '?')}
                  <span className="text-malicious"> · {r.status ?? r.error ?? 'FAIL'}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      <div className="absolute top-0 left-0 w-2 h-2 border-t border-l border-warning/50" />
      <div className="absolute top-0 right-0 w-2 h-2 border-t border-r border-warning/50" />
      <div className="absolute bottom-0 left-0 w-2 h-2 border-b border-l border-warning/50" />
      <div className="absolute bottom-0 right-0 w-2 h-2 border-b border-r border-warning/50" />
    </div>
  );
}
