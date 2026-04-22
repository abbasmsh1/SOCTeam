import React, { useEffect, useRef, useState } from 'react';
import { motion } from 'framer-motion';

interface StatCardProps {
  title: string;
  value: string;
  trendIndicator: string;
  icon: React.ReactNode;
  serialCode?: string;
}

/**
 * StatCard
 * --------
 * Instrument telemetry tile. Four animated corner brackets, a serial-number
 * readout, a tabular-figure count-up on the primary value, and a colored
 * status pill keyed to the trend.
 */
export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  trendIndicator,
  icon,
  serialCode,
}) => {
  const tone = toneFor(trendIndicator);
  const display = useCountUp(value);

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.45, ease: [0.2, 0.9, 0.2, 1] }}
      className={`panel ${tone.panelClass}`}
    >
      <span className="bracket-tr" aria-hidden />
      <span className="bracket-br" aria-hidden />

      {/* Serial / classification strip */}
      <div className="flex items-center justify-between mb-5 text-fog label">
        <span>{serialCode ?? `SN-${hashOf(title)}`}</span>
        <span className={`flex items-center gap-1 ${tone.pillClass}`}>
          <span className={`w-1.5 h-1.5 ${tone.dotClass} ${tone.pulse ? 'animate-pulse' : ''}`} />
          {trendIndicator}
        </span>
      </div>

      {/* Title — editorial italic for character */}
      <h4 className="font-serif italic text-paper/90 text-lg leading-tight mb-1">
        {title}
      </h4>

      {/* Primary value — huge tabular-figure display */}
      <div className="mt-3 flex items-end gap-3">
        <span className={`num font-display font-bold tracking-tight text-5xl md:text-6xl leading-none ${tone.valueClass}`}>
          {display}
        </span>
        <span className="text-fog mb-2">{icon}</span>
      </div>

      {/* Horizon line — minimal sparkline stand-in */}
      <div className="mt-6 h-px w-full bg-paper/5 relative overflow-hidden">
        <div
          className={`absolute left-0 top-0 h-full ${tone.barClass}`}
          style={{ width: tone.barWidth }}
        />
      </div>
      <div className="mt-2 flex justify-between label text-fog/70">
        <span>Δ-BASELINE</span>
        <span>{tone.barLabel}</span>
      </div>
    </motion.div>
  );
};

// ─── Helpers ─────────────────────────────────────────────

/** Animate count-up for numeric values; fall back to text otherwise. */
function useCountUp(value: string, durationMs = 700): string {
  const [rendered, setRendered] = useState(value);
  const fromRef = useRef(0);

  useEffect(() => {
    const n = parseNum(value);
    if (n === null) {
      setRendered(value);
      return;
    }
    const start = performance.now();
    const from = fromRef.current;
    fromRef.current = n;
    let raf = 0;
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / durationMs);
      const eased = 1 - Math.pow(1 - t, 3);
      const v = Math.round(from + (n - from) * eased);
      setRendered(v.toLocaleString());
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [value, durationMs]);

  return rendered;
}

function parseNum(v: string): number | null {
  const clean = v.replace(/,/g, '').trim();
  if (!/^-?\d+(\.\d+)?$/.test(clean)) return null;
  return Number(clean);
}

/** Small stable hash used to generate a deterministic SN label. */
function hashOf(s: string): string {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return Math.abs(h).toString(16).toUpperCase().slice(0, 4).padStart(4, '0');
}

function toneFor(ind: string) {
  const t = ind.toUpperCase();
  if (t === 'CRITICAL' || t === 'PRIORITY') {
    return {
      panelClass: 'panel--arterial',
      pillClass: 'text-malicious',
      dotClass: 'bg-malicious',
      pulse: true,
      valueClass: 'text-paper glow-arterial',
      barClass: 'bg-malicious',
      barWidth: '92%',
      barLabel: '+ HIGH',
    };
  }
  if (t === 'LIVE' || t === 'STABLE') {
    return {
      panelClass: 'panel--phosphor',
      pillClass: 'text-benign',
      dotClass: 'bg-benign',
      pulse: true,
      valueClass: 'text-paper',
      barClass: 'bg-benign/60',
      barWidth: '55%',
      barLabel: 'NOMINAL',
    };
  }
  if (t === 'NOMINAL' || t === 'IDLE' || t === 'ZERO') {
    return {
      panelClass: '',
      pillClass: 'text-fog',
      dotClass: 'bg-fog',
      pulse: false,
      valueClass: 'text-paper/85',
      barClass: 'bg-paper/25',
      barWidth: '18%',
      barLabel: 'LOW',
    };
  }
  return {
    panelClass: 'panel--ember',
    pillClass: 'text-warning',
    dotClass: 'bg-warning',
    pulse: true,
    valueClass: 'text-paper glow-ember',
    barClass: 'bg-warning/70',
    barWidth: '72%',
    barLabel: 'WATCH',
  };
}
