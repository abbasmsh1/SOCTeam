import React from 'react';
import { motion } from 'framer-motion';

interface StatCardProps {
  title: string;
  value: string;
  trendIndicator: string;
  icon: React.ReactNode;
}

export const StatCard: React.FC<StatCardProps> = ({ title, value, trendIndicator, icon }) => {
  const isPositive = trendIndicator === 'LIVE' || trendIndicator.startsWith('+');
  const isNegative = trendIndicator === 'CRITICAL' || trendIndicator.startsWith('-');

  // Determine color based on trendIndicator for the icon background
  const iconBgColor = isPositive ? 'bg-benign' : isNegative ? 'bg-malicious' : 'bg-slate-700';
  const iconColor = isPositive ? 'text-benign' : isNegative ? 'text-malicious' : 'text-slate-500';

  return (
    <motion.div 
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      className="hud-card group"
    >
      <div className="flex justify-between items-start mb-6">
        {/* New icon rendering block */}
        <div className={`p-3 rounded-xl bg-opacity-20 ${iconBgColor}`}>
          {React.cloneElement(icon as any, { className: `w-6 h-6 ${iconColor}` })}
        </div>
        <span className={`text-[10px] font-mono font-bold px-2 py-0.5 border ${
          isPositive ? 'border-benign/50 text-benign' : 
          isNegative ? 'border-malicious/50 text-malicious' : 
          'border-slate-700 text-slate-500'
        }`}>
          {trendIndicator}
        </span>
      </div>
      <h4 className="text-slate-500 text-[11px] uppercase tracking-widest font-bold mb-1">{title}</h4>
      <p className="text-3xl font-mono font-bold text-white tracking-tighter">{value}</p>
      
      {/* Decorative HUD fragments */}
      <div className="absolute top-0 right-0 w-1 h-1 bg-white/20" />
      <div className="absolute bottom-0 left-0 w-8 h-[1px] bg-white/10" />
    </motion.div>
  );
};
