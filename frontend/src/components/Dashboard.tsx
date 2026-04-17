/**
 * Dashboard.tsx
 * =============
 * Main SOC Mission Control dashboard. Displays:
 *   - System status header with health indicator
 *   - Primary telemetry grid (throughput, backlog, threats, agents)
 *   - Network traffic chart & remediation panel
 *   - Live threat monitor
 *   - Agent reasoning path visualization
 *   - Historical incident ledger (sidebar)
 */

import { Activity, Zap, AlertTriangle, Terminal, ChevronRight, FileText } from 'lucide-react';
import { XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area } from 'recharts';
import { Link } from 'react-router-dom';
import { useSocDashboard, type Report } from '../hooks/useSocDashboard';
import LiveMonitor from './LiveMonitor';
import AgentFlow from './AgentFlow';
import RemediationPanel from './RemediationPanel';
import BlockedIpsTable from './BlockedIpsTable';
import { StatCard } from './ui/StatCard';

/** Placeholder data for the network traffic chart until live data is wired. */
const MOCK_HISTORICAL_DATA = [
  { name: '04:00', flows: 400 },
  { name: '04:05', flows: 300 },
  { name: '04:10', flows: 520 },
  { name: '04:15', flows: 450 },
  { name: '04:20', flows: 600 },
  { name: '04:25', flows: 580 },
];

export default function Dashboard() {
  const { reports, stats, latestReport, error } = useSocDashboard();

  return (
    <div className="min-h-screen p-6 space-y-8 bg-transparent">

      {/* ── HUD Header ── */}
      <header className="flex items-center justify-between border-b border-white/10 pb-8">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <div className="w-1 h-6 bg-primary" />
            <h1 className="text-3xl font-black text-white tracking-widest uppercase italic">
              SOC <span className="text-primary">MISSION CONTROL</span>
            </h1>
          </div>
          <p className="text-slate-500 text-xs font-mono uppercase tracking-tighter">
            Real-time Autonomous Threat Response System v2.1 // PERSISTENT MEMORY ACTIVE
          </p>
        </div>

        {/* System health status indicator */}
        <div className="flex flex-col items-end gap-2">
            <div className="flex items-center gap-4 text-[10px] font-mono">
                <span className="text-slate-500 uppercase">System Status:</span>
                <span className={error ? "text-malicious animate-pulse" : "text-benign"}>
                    [{error ? "EXT_ERR" : "SECURED"}]
                </span>
            </div>
            {/* Mini progress bar (decorative health gauge) */}
            <div className="h-1 w-32 bg-white/5 relative">
                <div className="absolute top-0 left-0 h-full bg-primary w-2/3" />
            </div>
        </div>
      </header>

      {/* ── Primary Telemetry Grid ── */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <StatCard 
            title="Throughput (P/S)" 
            value={stats.packets_per_second.toLocaleString()} 
            trendIndicator={stats.packets_per_second > 0 ? "LIVE" : "IDLE"} 
            icon={<Activity className="text-primary" />} 
        />
        <StatCard 
            title="Analysis Backlog" 
            value={stats.pending_alerts.toString()} 
            trendIndicator={stats.pending_alerts > 0 ? "PRIORITY" : "NOMINAL"} 
            icon={<Zap className="text-warning" />} 
        />
        <StatCard 
            title="Confirmed Incursions" 
            value={stats.confirmed_threats.toString()} 
            trendIndicator={stats.confirmed_threats > 0 ? "CRITICAL" : "ZERO"} 
            icon={<AlertTriangle className={stats.confirmed_threats > 0 ? "text-malicious" : "text-slate-400"} />} 
        />
        <StatCard 
            title="Active Node Clusters" 
            value={stats.active_agents.toString()} 
            trendIndicator="STABLE" 
            icon={<Terminal className="text-slate-400" />} 
        />
      </div>

      {/* ── Operations Center Layout (two-column) ── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        
        {/* Left Column: Analytics & Execution */}
        <div className="lg:col-span-9 space-y-8">
          
          {/* Traffic chart + Remediation side-by-side */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">

            {/* Network Traffic Area Chart */}
            <div className="hud-card">
               <h3 className="text-xs font-black text-white mb-6 uppercase tracking-widest flex items-center gap-2">
                <div className="w-1.5 h-3 bg-primary" />
                Network Traffic Analysis
               </h3>
               <div className="h-[250px]">
                 <ResponsiveContainer width="100%" height="100%">
                   <AreaChart data={MOCK_HISTORICAL_DATA}>
                     <defs>
                       <linearGradient id="colorFlows" x1="0" y1="0" x2="0" y2="1">
                         <stop offset="5%" stopColor="hsl(var(--primary))" stopOpacity={0.2}/>
                         <stop offset="95%" stopColor="hsl(var(--primary))" stopOpacity={0}/>
                       </linearGradient>
                     </defs>
                     <CartesianGrid strokeDasharray="2 2" stroke="#ffffff05" vertical={false} />
                     <XAxis dataKey="name" stroke="#333" fontSize={10} fontStyle="italic" />
                     <YAxis stroke="#333" fontSize={10} />
                     <Tooltip 
                       contentStyle={{ backgroundColor: '#000', border: '1px solid #333', borderRadius: '0' }}
                       itemStyle={{ color: '#fff' }}
                     />
                     <Area type="stepBefore" dataKey="flows" stroke="hsl(var(--primary))" strokeWidth={2} fillOpacity={1} fill="url(#colorFlows)" />
                   </AreaChart>
                 </ResponsiveContainer>
               </div>
            </div>

            {/* Active remediation actions panel */}
            <RemediationPanel />
          </div>

          {/* Real-time threat monitor feed */}
          <LiveMonitor />

          {/* Full remediation action log table */}
          <BlockedIpsTable />
          
          {/* Agent Reasoning Path – shows which tier processed the latest report */}
          <div className="hud-card border-primary/20">
             <div className="flex items-center justify-between mb-8 border-b border-white/5 pb-4">
                 <h3 className="text-xs font-black text-white uppercase tracking-widest flex items-center gap-2">
                    <div className="w-1.5 h-3 bg-primary" />
                    Agent Reasoning Path
                 </h3>
                 {latestReport && (
                    <div className="text-[10px] font-mono text-slate-500 uppercase">
                        Current Frame: <span className="text-white italic">{latestReport.name}</span>
                    </div>
                 )}
             </div>
             <AgentFlow latestReport={latestReport} />
          </div>
        </div>

        {/* Right Column: Historical Incident Ledger (sticky sidebar) */}
        <aside className="lg:col-span-3 lg:sticky lg:top-8 h-fit space-y-6">
            <div className="hud-card bg-primary/5 border-primary/20">
                <h3 className="text-xs font-black text-white mb-6 uppercase tracking-widest flex items-center gap-2">
                    <FileText className="text-primary" size={14} />
                    Incident Ledger
                </h3>
                <div className="space-y-3">
                    {reports.length > 0 ? (
                    reports.map((report) => (
                        <ReportLink key={report.id} report={report} />
                    ))
                    ) : (
                    <div className="text-center py-12 border border-dashed border-white/10 opacity-30 italic text-[10px]">
                        SCANNING FOR INCIDENTS...
                    </div>
                    )}
                </div>
            </div>

            {/* Decorative system metadata footer */}
            <div className="opacity-20 text-[9px] font-mono leading-tight uppercase tracking-tighter">
                [SYSTEM_ID: REDACTED]<br/>
                [LOC: SERVER_NODE_A]<br/>
                [TIME_ELAPSED: 12.44S]
            </div>
        </aside>

      </div>
    </div>
  );
}

/**
 * ReportLink
 * ----------
 * Renders a single incident report entry in the sidebar ledger.
 * Highlights critical reports with a red badge.
 */
function ReportLink({ report }: { report: Report }) {
  const isCritical = report.final_severity === 'CRITICAL' || (report.name && report.name.includes('Report'));
  
  return (
    <Link to={`/report/${report.id}`} className="block border border-white/5 bg-white/5 hover:border-primary/40 p-3 group transition-all">
      <div className="flex items-center justify-between mb-2">
        <span className={`text-[9px] font-bold px-1 ${isCritical ? 'bg-malicious text-white' : 'bg-slate-800 text-slate-400'}`}>
          {isCritical ? 'THREAT_MATCH' : 'SCAN_PASS'}
        </span>
        <span className="text-[9px] font-mono text-slate-600">
            {new Date(report.created_at).toLocaleTimeString([], { hour12: false })}
        </span>
      </div>
      <h5 className="text-[11px] font-bold text-slate-300 group-hover:text-primary transition-colors truncate">
        {report.name || "UNIDENTIFIED_ALERT"}
      </h5>
      <div className="mt-3 flex justify-between items-center opacity-0 group-hover:opacity-100 transition-opacity">
          <span className="text-[8px] font-bold text-primary italic uppercase tracking-widest">Open Record</span>
          <ChevronRight size={10} className="text-primary" />
      </div>
    </Link>
  );
}
