import React, { useState, useEffect } from 'react';
import { Shield, Activity, Zap, AlertTriangle, Terminal, ChevronRight, FileText } from 'lucide-react';
import { XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area } from 'recharts';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import { idsApi } from '../utils/api';
import LiveMonitor from './LiveMonitor';
import AgentFlow from './AgentFlow';
import RemediationPanel from './RemediationPanel';

interface Report {
  id: string;
  name: string;
  created_at: string;
}

// Mock data for initial state
const MOCK_STATS = [
  { name: '04:00', flows: 400, threats: 24 },
  { name: '04:05', flows: 300, threats: 13 },
  { name: '04:10', flows: 520, threats: 45 },
  { name: '04:15', flows: 450, threats: 32 },
  { name: '04:20', flows: 600, threats: 12 },
  { name: '04:25', flows: 580, threats: 8 },
];

export default function Dashboard() {
  const [reports, setReports] = useState<Report[]>([]);
  const [stats, setStats] = useState({
    packets_per_second: 0,
    pending_alerts: 0,
    confirmed_threats: 0,
    active_agents: 0
  });

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [reportsRes, statsRes] = await Promise.all([
          idsApi.getReports(),
          idsApi.getStats()
        ]);
        setReports(reportsRes.data);
        setStats(statsRes.data);
      } catch (error) {
        console.error("Failed to fetch dashboard data:", error);
      }
    };
    fetchData();
    const interval = setInterval(fetchData, 2000); // Poll every 2s for live feel
    return () => clearInterval(interval);
  }, []);

  // Get the latest report for workflow visualization if available
  const latestReport = reports.length > 0 ? reports[0] : null;

  return (
    <div className="min-h-screen p-6 space-y-6">
      {/* Header */}
      <header className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Shield className="text-primary w-8 h-8" />
            SOC <span className="text-primary">MISSION CONTROL</span>
          </h1>
          <p className="text-slate-500 text-sm">Real-time Agentic Threat Detection & Response</p>
        </div>
        <div className="flex gap-4">
          <div className="glass px-4 py-2 rounded-lg flex items-center gap-3">
            <div className={`w-2 h-2 rounded-full ${stats.packets_per_second > 0 ? "bg-benign animate-pulse" : "bg-slate-500"}`} />
            <span className="text-sm font-medium">SYSTEM HEALTH: {stats.confirmed_threats > 0 ? "THREAT DETECTED" : "OPTIMAL"}</span>
          </div>
        </div>
      </header>

      {/* Top Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <StatCard title="Packets/Sec" value={stats.packets_per_second.toLocaleString()} delta={stats.packets_per_second > 0 ? "LIVE" : "IDLE"} icon={<Activity className="text-primary" />} />
        <StatCard title="Pending Alerts" value={stats.pending_alerts.toString()} delta={stats.pending_alerts > 0 ? "Analysis Required" : "Clear"} icon={<Zap className="text-warning" />} />
        <StatCard title="Confirmed Threats" value={stats.confirmed_threats.toString()} delta={stats.confirmed_threats > 0 ? "CRITICAL" : "None"} icon={<AlertTriangle className={stats.confirmed_threats > 0 ? "text-malicious" : "text-slate-400"} />} />
        <StatCard title="Active Agents" value={stats.active_agents.toString()} delta="Online" icon={<Terminal className="text-slate-400" />} />
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="lg:col-span-3 space-y-6">
          {/* Traffic Analytics */}
          <div className="glass rounded-2xl p-6">
            <h3 className="text-lg font-bold text-white mb-6">Traffic Analysis</h3>
            <div className="h-[300px]">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={MOCK_STATS}>
                  <defs>
                    <linearGradient id="colorFlows" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" />
                  <XAxis dataKey="name" stroke="#64748b" />
                  <YAxis stroke="#64748b" />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#121216', border: '1px solid #ffffff10' }}
                    itemStyle={{ color: '#fff' }}
                  />
                  <Area type="monotone" dataKey="flows" stroke="#3b82f6" fillOpacity={1} fill="url(#colorFlows)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
          
          {/* Real-time Monitor and Flow integrated here */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <RemediationPanel />
            <LiveMonitor />
          </div>
          <AgentFlow latestReport={latestReport} />
        </div>

        {/* Live Feed Sidebar */}
        <div className="glass rounded-2xl p-6 h-fit sticky top-6">
          <h3 className="text-lg font-bold text-white mb-6 flex items-center gap-2">
            <FileText className="text-primary" size={18} />
            Recent Reports
          </h3>
          <div className="space-y-4">
             {reports.length > 0 ? (
               reports.map((report) => (
                 <ReportLink 
                    key={report.id} 
                    id={report.id} 
                    label={report.name.includes('Report') ? 'INCIDENT DETECTED' : report.name} 
                    severity="HIGH" 
                    time={new Date(report.created_at).toLocaleTimeString()} 
                 />
               ))
             ) : (
               <div className="text-center py-8 text-slate-500 text-xs italic">
                 No reports generated yet.
               </div>
             )}
          </div>
        </div>
      </div>
    </div>
  );
}

function ReportLink({ id, label, severity, time }: { id: string, label: string, severity: string, time: string }) {
  const colorMap = {
    CRITICAL: 'bg-malicious',
    HIGH: 'bg-orange-500',
    MEDIUM: 'bg-warning',
    LOW: 'bg-slate-500'
  };

  return (
    <Link to={`/report/${id}`} className="flex items-center gap-4 p-3 rounded-xl hover:bg-white/5 transition-colors cursor-pointer group">
      <div className={`w-2 h-10 rounded-full ${colorMap[severity as keyof typeof colorMap]}`} />
      <div className="flex-1">
        <h5 className="text-sm font-bold text-white group-hover:text-primary transition-colors truncate max-w-[150px]">{label}</h5>
        <div className="flex items-center gap-2 mt-1">
          <span className="text-[10px] uppercase font-bold text-slate-500">{severity}</span>
          <span className="w-1 h-1 rounded-full bg-slate-700" />
          <span className="text-[10px] text-slate-500">{time}</span>
        </div>
      </div>
      <ChevronRight className="text-slate-700 w-4 h-4" />
    </Link>
  );
}

function StatCard({ title, value, delta, icon }: { title: string, value: string, delta: string, icon: React.ReactNode }) {
  return (
    <motion.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass rounded-2xl p-6 hover:border-primary/50 transition-colors"
    >
      <div className="flex justify-between items-start mb-4">
        <div className="p-2 rounded-lg bg-white/5">{icon}</div>
        <span className={`text-xs font-bold ${delta.startsWith('+') ? 'text-benign' : delta.startsWith('-') ? 'text-malicious' : 'text-slate-500'}`}>
          {delta}
        </span>
      </div>
      <h4 className="text-slate-500 text-sm font-medium">{title}</h4>
      <p className="text-2xl font-bold text-white mt-1">{value}</p>
    </motion.div>
  );
}
