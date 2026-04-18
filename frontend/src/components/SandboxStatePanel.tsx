/**
 * SandboxStatePanel.tsx
 * =====================
 * Displays the live state of the DefensiveActionSandbox:
 *   - Blocked IP addresses
 *   - Active firewall rules
 *   - Rate-limited hosts
 *   - Total action count
 *
 * Also exposes a "Clear Sandbox" button that calls POST /sandbox/clear,
 * resetting all in-memory defensive rules (useful during rapid test cycles).
 *
 * Polls the backend every 5 seconds via GET /sandbox/state.
 */

import { useState, useEffect, useCallback } from 'react';
import { Shield, Ban, Flame, Gauge, Trash2, RefreshCw } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { idsApi } from '../utils/api';

// ── Types ────────────────────────────────────────────────────────────────────

interface FirewallRule {
  rule_id?: string;
  action?: string;      // DROP | REJECT | ALLOW
  source_ip?: string;
  destination_ip?: string;
  port?: number | string;
  protocol?: string;
  description?: string;
  created_at?: string;
}

interface SandboxState {
  blocked_ips: string[];
  firewall_rules: FirewallRule[];
  rate_limited_hosts: string[];
  total_actions: number;
  sandbox_active?: boolean;
  last_updated?: string;
}

const EMPTY_STATE: SandboxState = {
  blocked_ips: [],
  firewall_rules: [],
  rate_limited_hosts: [],
  total_actions: 0,
};

const POLL_INTERVAL_MS = 5_000;

// ── Component ────────────────────────────────────────────────────────────────

export default function SandboxStatePanel() {
  const [state, setState] = useState<SandboxState>(EMPTY_STATE);
  const [loading, setLoading] = useState(true);
  const [clearing, setClearing] = useState(false);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  // Fetch sandbox state from backend
  const fetchState = useCallback(async () => {
    try {
      const res = await idsApi.getSandboxState();
      const data = res.data ?? {};
      setState({
        blocked_ips: Array.isArray(data.blocked_ips) ? data.blocked_ips : [],
        firewall_rules: Array.isArray(data.firewall_rules) ? data.firewall_rules : [],
        rate_limited_hosts: Array.isArray(data.rate_limited_hosts) ? data.rate_limited_hosts : [],
        total_actions: typeof data.total_actions === 'number' ? data.total_actions : 0,
        sandbox_active: data.sandbox_active ?? true,
        last_updated: data.last_updated,
      });
      setLastRefresh(new Date());
    } catch (err) {
      console.error('[SandboxStatePanel] Failed to fetch sandbox state:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  // Poll on mount
  useEffect(() => {
    fetchState();
    const interval = setInterval(fetchState, POLL_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [fetchState]);

  // Clear sandbox action
  const handleClear = async () => {
    if (clearing) return;
    setClearing(true);
    try {
      await idsApi.clearSandbox();
      // Optimistic reset
      setState(EMPTY_STATE);
      setLastRefresh(new Date());
    } catch (err) {
      console.error('[SandboxStatePanel] Clear failed:', err);
    } finally {
      setClearing(false);
    }
  };

  const totalRules =
    state.blocked_ips.length +
    state.firewall_rules.length +
    state.rate_limited_hosts.length;

  return (
    <div className="hud-card border-primary/20 relative group overflow-hidden">

      {/* ── Header ── */}
      <div className="flex items-center justify-between mb-6 border-b border-white/5 pb-4">
        <h3 className="text-sm font-black text-white uppercase tracking-widest flex items-center gap-2">
          <Shield className="text-primary" size={16} />
          Defensive Sandbox State
        </h3>
        <div className="flex items-center gap-3">
          {/* Live indicator */}
          <span className="text-[10px] font-mono text-primary/60 uppercase animate-pulse">
            [SANDBOX_ACTIVE]
          </span>
          {/* Last refresh */}
          {lastRefresh && (
            <span className="text-[9px] font-mono text-slate-600 hidden sm:inline">
              {lastRefresh.toLocaleTimeString([], { hour12: false })}
            </span>
          )}
          {/* Manual refresh */}
          <button
            onClick={fetchState}
            title="Refresh sandbox state"
            className="text-slate-500 hover:text-primary transition-colors"
          >
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {/* ── Metric strip ── */}
      <div className="grid grid-cols-3 gap-3 mb-6">
        <MetricBadge
          icon={<Ban size={14} className="text-malicious" />}
          label="Blocked IPs"
          value={state.blocked_ips.length}
          accent="malicious"
        />
        <MetricBadge
          icon={<Flame size={14} className="text-warning" />}
          label="Firewall Rules"
          value={state.firewall_rules.length}
          accent="warning"
        />
        <MetricBadge
          icon={<Gauge size={14} className="text-primary" />}
          label="Rate Limits"
          value={state.rate_limited_hosts.length}
          accent="primary"
        />
      </div>

      {/* ── Content (empty vs populated) ── */}
      {loading && totalRules === 0 ? (
        <div className="text-center py-8 text-slate-600 font-mono text-[10px] uppercase tracking-widest animate-pulse">
          Connecting to sandbox...
        </div>
      ) : totalRules === 0 ? (
        <div className="text-center py-8 border border-dashed border-white/10 opacity-30 italic text-[10px] font-mono uppercase">
          Sandbox is clean — no active rules
        </div>
      ) : (
        <div className="space-y-4 max-h-64 overflow-y-auto pr-1 scrollbar-thin scrollbar-thumb-white/10">

          {/* Blocked IPs */}
          {state.blocked_ips.length > 0 && (
            <Section title="Blocked IPs" accent="malicious">
              <AnimatePresence initial={false}>
                {state.blocked_ips.map((ip, i) => (
                  <motion.div
                    key={ip + i}
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: 8 }}
                    className="flex items-center gap-2 py-1.5 border-b border-white/5 last:border-0"
                  >
                    <Ban size={10} className="text-malicious shrink-0" />
                    <span className="text-[11px] font-mono text-white bg-malicious/10 px-2 py-0.5 border border-malicious/20">
                      {ip}
                    </span>
                  </motion.div>
                ))}
              </AnimatePresence>
            </Section>
          )}

          {/* Firewall Rules */}
          {state.firewall_rules.length > 0 && (
            <Section title="Firewall Rules" accent="warning">
              <AnimatePresence initial={false}>
                {state.firewall_rules.map((rule, i) => (
                  <motion.div
                    key={(rule.rule_id ?? '') + i}
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: 8 }}
                    className="py-1.5 border-b border-white/5 last:border-0"
                  >
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`text-[10px] font-bold font-mono px-1.5 py-0.5 border ${
                        rule.action === 'DROP'
                          ? 'text-malicious border-malicious/40 bg-malicious/10'
                          : rule.action === 'ALLOW'
                          ? 'text-benign border-benign/40 bg-benign/10'
                          : 'text-warning border-warning/40 bg-warning/10'
                      }`}>
                        {rule.action ?? 'UNKNOWN'}
                      </span>
                      {rule.source_ip && (
                        <span className="text-[10px] font-mono text-slate-400">
                          src: <span className="text-white">{rule.source_ip}</span>
                        </span>
                      )}
                      {rule.port && (
                        <span className="text-[10px] font-mono text-slate-400">
                          :{rule.port}
                        </span>
                      )}
                      {rule.protocol && (
                        <span className="text-[10px] font-mono text-slate-500 uppercase">
                          ({rule.protocol})
                        </span>
                      )}
                    </div>
                    {rule.description && (
                      <p className="text-[10px] text-slate-600 mt-0.5 truncate" title={rule.description}>
                        {rule.description}
                      </p>
                    )}
                  </motion.div>
                ))}
              </AnimatePresence>
            </Section>
          )}

          {/* Rate-limited Hosts */}
          {state.rate_limited_hosts.length > 0 && (
            <Section title="Rate-Limited Hosts" accent="primary">
              <AnimatePresence initial={false}>
                {state.rate_limited_hosts.map((host, i) => (
                  <motion.div
                    key={host + i}
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: 8 }}
                    className="flex items-center gap-2 py-1.5 border-b border-white/5 last:border-0"
                  >
                    <Gauge size={10} className="text-primary shrink-0" />
                    <span className="text-[11px] font-mono text-white/80">{host}</span>
                  </motion.div>
                ))}
              </AnimatePresence>
            </Section>
          )}
        </div>
      )}

      {/* ── Footer: total + clear button ── */}
      <div className="flex items-center justify-between mt-5 pt-4 border-t border-white/5">
        <div className="text-[10px] font-mono text-slate-500 uppercase">
          Total Actions Executed:{' '}
          <span className="text-white font-bold">{state.total_actions}</span>
        </div>
        <button
          id="clear-sandbox-btn"
          onClick={handleClear}
          disabled={clearing || totalRules === 0}
          className={`
            flex items-center gap-1.5 text-[10px] font-bold font-mono uppercase tracking-widest
            px-3 py-1.5 border transition-all
            ${
              totalRules === 0
                ? 'text-slate-700 border-slate-800 cursor-not-allowed'
                : 'text-malicious border-malicious/40 hover:bg-malicious/10 active:scale-95 cursor-pointer'
            }
          `}
        >
          {clearing ? (
            <RefreshCw size={10} className="animate-spin" />
          ) : (
            <Trash2 size={10} />
          )}
          {clearing ? 'Clearing...' : 'Clear Sandbox'}
        </button>
      </div>

      {/* ── HUD corner brackets ── */}
      <div className="absolute top-0 left-0 w-2 h-2 border-t border-l border-primary/50" />
      <div className="absolute top-0 right-0 w-2 h-2 border-t border-r border-primary/50" />
      <div className="absolute bottom-0 left-0 w-2 h-2 border-b border-l border-primary/50" />
      <div className="absolute bottom-0 right-0 w-2 h-2 border-b border-r border-primary/50" />
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function Section({
  title,
  accent,
  children,
}: {
  title: string;
  accent: 'malicious' | 'warning' | 'primary';
  children: React.ReactNode;
}) {
  const accentClass =
    accent === 'malicious'
      ? 'text-malicious'
      : accent === 'warning'
      ? 'text-warning'
      : 'text-primary';

  return (
    <div>
      <p className={`text-[9px] font-bold font-mono uppercase tracking-widest mb-1 ${accentClass}`}>
        ── {title}
      </p>
      {children}
    </div>
  );
}

function MetricBadge({
  icon,
  label,
  value,
  accent,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  accent: 'malicious' | 'warning' | 'primary';
}) {
  const borderClass =
    accent === 'malicious'
      ? 'border-malicious/20'
      : accent === 'warning'
      ? 'border-warning/20'
      : 'border-primary/20';

  return (
    <div className={`bg-black/40 border ${borderClass} px-3 py-2`}>
      <div className="flex items-center gap-1.5 mb-1">
        {icon}
        <span className="text-[9px] font-mono text-slate-500 uppercase">{label}</span>
      </div>
      <p className="text-xl font-black text-white font-mono">{value}</p>
    </div>
  );
}
