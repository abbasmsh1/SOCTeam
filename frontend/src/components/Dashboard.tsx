/**
 * Dashboard.tsx
 * =============
 * SOC Mission Control — "War Room / Classified Instrument Panel" aesthetic.
 *
 *   Header        ── editorial kicker + display headline + status chevrons
 *   Ticker strip  ── continuously scrolling telemetry marquee
 *   Stat grid     ── four StatCards with animated count-up
 *   Ops center    ── two-column layout of live feeds + agent pipeline
 *   Ledger aside  ── sticky sidebar incident ledger
 */

import { useEffect, useState } from 'react';
import {
  Activity, Zap, AlertTriangle, Terminal, ChevronRight, FileText, ShieldAlert,
} from 'lucide-react';
import {
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area,
} from 'recharts';
import { Link } from 'react-router-dom';
import { useSocStream, type Report } from '../hooks/useSocStream';
import { idsApi } from '../utils/api';
import LiveMonitor from './LiveMonitor';
import AgentFlow from './AgentFlow';
import RemediationPanel from './RemediationPanel';
import BlockedIpsTable from './BlockedIpsTable';
import SandboxStatePanel from './SandboxStatePanel';
import DispatchAlert from './DispatchAlert';
import RLStatsPanel from './RLStatsPanel';
import TopThreatsPanel from './TopThreatsPanel';
import { StatCard } from './ui/StatCard';
import { Panel } from './ui/Panel';
import { Ticker, type TickerItem } from './ui/Ticker';

export default function Dashboard() {
  const {
    reports, stats, traffic, sandbox, remediationLogs, latestReport,
    error, connected,
  } = useSocStream();
  const [pendingCount, setPendingCount] = useState(0);
  const [clock, setClock] = useState(() => new Date());

  // Pending quarantine count — drives the red "QUARANTINE" chevron top-right.
  useEffect(() => {
    const fetchPending = async () => {
      try {
        const res = await idsApi.getQuarantine();
        const list = Array.isArray(res.data) ? res.data : [];
        setPendingCount(list.filter((e: any) => e.status === 'PENDING_HUMAN').length);
      } catch { /* non-critical */ }
    };
    fetchPending();
    const id = setInterval(fetchPending, 5000);
    return () => clearInterval(id);
  }, []);

  // Wall clock — refreshes every second for the station-ID line.
  useEffect(() => {
    const id = setInterval(() => setClock(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  const linkState =
    error    ? { text: 'LINK·DEGRADED', tone: 'text-malicious animate-pulse' }
  : connected? { text: 'LINK·SECURED',  tone: 'text-benign glow-phosphor' }
  :            { text: 'LINK·PENDING',  tone: 'text-warning animate-pulse' };

  const tickerItems: TickerItem[] = [
    { label: 'UPLINK',       value: linkState.text, tone: connected ? 'phosphor' : 'radar' },
    { label: 'THROUGHPUT',   value: `${stats.packets_per_second.toLocaleString()} P/S`, tone: 'default' },
    // NOTE: `EVENTS·WINDOW` is live-event queue depth from /events/stats —
    // this is NOT the quarantine count. Quarantine lives in `REVIEW·PENDING`.
    { label: 'EVENTS·WINDOW', value: stats.pending_alerts, tone: stats.pending_alerts > 0 ? 'radar' : 'default' },
    { label: 'INCURSIONS',   value: stats.confirmed_threats, tone: stats.confirmed_threats > 0 ? 'arterial' : 'default' },
    { label: 'NODES',        value: stats.active_agents, tone: 'ember' },
    { label: 'BLOCKED',      value: sandbox.blocked_ips.length, tone: 'phosphor' },
    { label: 'RULES',        value: sandbox.firewall_rules.length, tone: 'default' },
    { label: 'REVIEW·PENDING', value: pendingCount, tone: pendingCount > 0 ? 'arterial' : 'default' },
    { label: 'UTC',          value: clock.toISOString().slice(11, 19), tone: 'default' },
  ];

  return (
    <div className="min-h-screen bg-transparent">
      {/* ── Editorial Header ───────────────────────────── */}
      <header className="px-6 pt-10 pb-6">
        <div className="flex items-start justify-between gap-8 flex-wrap">
          <div className="max-w-3xl">
            <div className="flex items-center gap-3 mb-3">
              <span className="w-2.5 h-2.5 bg-primary" />
              <span className="label text-primary glow-ember">MISSION CONTROL // TIER·SIGMA CLEARANCE</span>
              <span className="label text-fog hidden sm:inline">/ SOC·v2.1</span>
            </div>
            <h1 className="font-display font-bold tracking-tight text-paper text-5xl md:text-6xl leading-[0.95]">
              Autonomous Threat Response
              <span className="block stamp text-paper/80 font-normal text-3xl md:text-4xl mt-1">
                <span className="text-primary">in situ</span> — real-time, persistent, accountable.
              </span>
            </h1>
            <p className="mt-4 label text-fog max-w-xl">
              sensor array is continuously assessed by a tiered analyst pipeline;
              decisions are <span className="text-paper">recorded</span>,
              <span className="text-paper"> reversible</span>, and
              <span className="text-paper"> legible</span>.
            </p>
          </div>

          {/* Right: status chevrons */}
          <div className="flex flex-col items-end gap-3">
            <div className="flex items-center gap-2">
              <Link
                to="/quarantine"
                className={`flex items-center gap-1.5 border px-2.5 py-1 label transition-colors ${
                  pendingCount > 0
                    ? 'text-malicious border-malicious/60 bg-malicious/10 animate-pulse'
                    : 'text-fog border-paper/10 hover:border-primary/40 hover:text-primary'
                }`}
              >
                <ShieldAlert size={11} /> QUARANTINE
                <span className={`ml-1 px-1 num ${pendingCount > 0 ? 'bg-malicious text-ink' : 'bg-graphite text-fog'}`}>
                  {pendingCount}
                </span>
              </Link>
              <span className={`label border px-2.5 py-1 ${linkState.tone} border-paper/10`}>
                [{linkState.text}]
              </span>
            </div>

            <div className="flex items-center gap-2 label text-fog">
              <span>STN-A · {clock.toLocaleDateString([], { year: 'numeric', month: '2-digit', day: '2-digit' }).replace(/\//g, '·')}</span>
              <span className="num text-paper">{clock.toLocaleTimeString([], { hour12: false })}</span>
            </div>

            <div className="h-1 w-40 bg-paper/5 relative overflow-hidden">
              <div className="absolute top-0 left-0 h-full bg-primary"
                   style={{ width: connected ? '100%' : error ? '8%' : '45%', transition: 'width 0.8s ease' }} />
            </div>
          </div>
        </div>
      </header>

      {/* ── Ticker Strip ───────────────────────────────── */}
      <Ticker items={tickerItems} />

      {/* ── Body ───────────────────────────────────────── */}
      <div className="p-6 space-y-8 mt-6">

        {/* ── Primary Telemetry Grid ─────────────────── */}
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          <StatCard
            title="Throughput"
            value={stats.packets_per_second.toLocaleString()}
            trendIndicator={stats.packets_per_second > 0 ? 'LIVE' : 'IDLE'}
            icon={<Activity size={18} />}
            serialCode="T-001·P/S"
          />
          <StatCard
            title="Analysis Backlog"
            value={stats.pending_alerts.toString()}
            trendIndicator={stats.pending_alerts > 0 ? 'PRIORITY' : 'NOMINAL'}
            icon={<Zap size={18} />}
            serialCode="T-002·QUE"
          />
          <StatCard
            title="Confirmed Incursions"
            value={stats.confirmed_threats.toString()}
            trendIndicator={stats.confirmed_threats > 0 ? 'CRITICAL' : 'ZERO'}
            icon={<AlertTriangle size={18} />}
            serialCode="T-003·HIT"
          />
          <StatCard
            title="Active Node Clusters"
            value={stats.active_agents.toString()}
            trendIndicator="STABLE"
            icon={<Terminal size={18} />}
            serialCode="T-004·NOD"
          />
        </div>

        {/* ── Ops Center ─────────────────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">

          {/* Left: live feeds & agent pipeline */}
          <div className="lg:col-span-9 space-y-6">

            {/* Traffic + Remediation */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Panel label="Network Traffic Analysis" icon={<Activity size={14} />} meta={<span>60m</span>}>
                <div className="h-[240px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={traffic} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
                      <defs>
                        <linearGradient id="colorFlows" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%"  stopColor="#f97316" stopOpacity={0.35} />
                          <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="2 3" stroke="#ffffff08" vertical={false} />
                      <XAxis dataKey="name" stroke="#8a869077" fontSize={10}
                             tickLine={false} axisLine={{ stroke: '#3d3b44' }} />
                      <YAxis stroke="#8a869077" fontSize={10}
                             tickLine={false} axisLine={false} />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#08070aF2',
                          border: '1px solid #f97316',
                          borderRadius: 0,
                          color: '#eee8dc',
                          fontFamily: 'IBM Plex Mono, monospace',
                          fontSize: 11,
                        }}
                        cursor={{ stroke: '#f9731655', strokeWidth: 1 }}
                        itemStyle={{ color: '#eee8dc' }}
                        labelStyle={{ color: '#8a8690' }}
                      />
                      <Area
                        type="stepBefore"
                        dataKey="flows"
                        stroke="#f97316"
                        strokeWidth={1.5}
                        fill="url(#colorFlows)"
                        animationDuration={600}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </Panel>
              <RemediationPanel />
            </div>

            <LiveMonitor />
            <TopThreatsPanel />
            <BlockedIpsTable logs={remediationLogs} />
            <SandboxStatePanel sandbox={sandbox} />
            <DispatchAlert />
            <RLStatsPanel />

            {/* Agent Reasoning Path */}
            <Panel
              accent="ember"
              label="Agent Reasoning Path"
              icon={<ChevronRight size={14} />}
              meta={
                latestReport ? (
                  <span>
                    frame: <span className="stamp text-paper">{latestReport.name}</span>
                  </span>
                ) : <span>idle</span>
              }
            >
              <AgentFlow latestReport={latestReport} />
            </Panel>
          </div>

          {/* Right: sticky incident ledger */}
          <aside className="lg:col-span-3 lg:sticky lg:top-8 h-fit space-y-5">
            <Panel
              accent="ember"
              label="Incident Ledger"
              icon={<FileText size={13} />}
              meta={<span className="num">{reports.length.toString().padStart(3, '0')}</span>}
            >
              <div className="space-y-2.5 max-h-[70vh] overflow-y-auto pr-1">
                {reports.length > 0 ? (
                  reports.map((report) => <ReportLink key={report.id} report={report} />)
                ) : (
                  <div className="text-center py-10 border border-dashed border-paper/8 label text-fog/40 tracking-[0.3em]">
                    scanning for incidents…
                  </div>
                )}
              </div>
            </Panel>

            <div className="px-1 stamp text-paper/30 text-[12px] leading-relaxed">
              <span className="label text-fog/50 block mb-2">station metadata</span>
              this terminal is a <span className="text-paper/60">read-write</span> operator console.
              every intervention you authorize is appended to the immutable
              incident ledger and, where reversible, can be revoked from the
              quarantine page.
            </div>
          </aside>
        </div>
      </div>
    </div>
  );
}

/** Single incident row in the sticky ledger sidebar. */
function ReportLink({ report }: { report: Report }) {
  const isCritical =
    report.final_severity === 'CRITICAL' ||
    (report.name && report.name.includes('Report'));

  return (
    <Link
      to={`/report/${report.id}`}
      className="block border border-paper/5 bg-paper/[0.015] hover:border-primary/50 hover:bg-paper/[0.04] p-3 group transition-all"
    >
      <div className="flex items-center justify-between mb-1.5">
        <span className={`label px-1 py-0.5 ${
          isCritical ? 'bg-malicious text-paper' : 'bg-graphite text-fog'
        }`}>
          {isCritical ? 'THREAT·MATCH' : 'SCAN·PASS'}
        </span>
        <span className="num text-[10px] text-fog/60">
          {new Date(report.created_at).toLocaleTimeString([], { hour12: false })}
        </span>
      </div>
      <h5 className="stamp text-[13px] text-paper/85 group-hover:text-primary transition-colors truncate leading-snug">
        {report.name || 'unidentified alert'}
      </h5>
      <div className="mt-2 flex justify-between items-center opacity-0 group-hover:opacity-100 transition-opacity">
        <span className="label text-primary">open record</span>
        <ChevronRight size={11} className="text-primary" />
      </div>
    </Link>
  );
}
