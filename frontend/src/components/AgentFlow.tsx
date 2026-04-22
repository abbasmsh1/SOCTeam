import { motion } from 'framer-motion';

interface AgentFlowProps {
  latestReport: any;
}

type AgentId = 'ids' | 'tier1' | 'tier2' | 'tier3' | 'warroom';

interface AgentNode {
  id: AgentId;
  label: string;
  sub: string;
}

const AGENTS: AgentNode[] = [
  { id: 'ids',     label: 'IDS SENSOR',    sub: 'Ingress' },
  { id: 'tier1',   label: 'T1 ANALYST',    sub: 'Triage' },
  { id: 'tier2',   label: 'T2 ANALYST',    sub: 'Correlate' },
  { id: 'tier3',   label: 'T3 ANALYST',    sub: 'Hunt' },
  { id: 'warroom', label: 'WAR ROOM',      sub: 'Response' },
];

/** Palette — all from the design tokens. */
const C = {
  paper:    '#eee8dc',
  fog:      '#8a8690',
  steel:    '#3d3b44',
  graphite: '#1d1a20',
  ember:    '#f97316',
  phosphor: '#4ade80',
  warning:  '#facc15',
  arterial: '#e11d48',
} as const;

/**
 * AgentFlow
 * ---------
 * Horizontal SVG pipeline with active stage highlighting. The traveling
 * photon along each active edge is a small animated circle on a straight
 * path — keeps GPU usage low while still feeling alive.
 */
export default function AgentFlow({ latestReport }: AgentFlowProps) {
  const activeFlags = {
    ids:     true,
    tier1:   true,
    tier2:   !!latestReport?.escalated_to_tier2,
    tier3:   !!latestReport?.escalated_to_tier3,
    warroom: !!latestReport?.war_room_triggered,
  } as Record<AgentId, boolean>;

  const colorFor = (id: AgentId) => {
    if (!activeFlags[id]) return { fill: C.graphite, stroke: C.steel, text: C.fog };
    switch (id) {
      case 'ids':     return { fill: '#0b1820', stroke: '#3b82f6', text: '#93c5fd' };
      case 'tier1':   return { fill: '#1a0f02', stroke: C.ember, text: C.paper };
      case 'tier2':   return { fill: '#1a1406', stroke: C.warning, text: C.paper };
      case 'tier3':   return { fill: '#1f0a05', stroke: C.ember, text: C.paper };
      case 'warroom': return { fill: '#1a0710', stroke: C.arterial, text: C.paper };
    }
  };

  const edgeActive = (from: AgentId, to: AgentId): boolean => {
    if (!latestReport) return from === 'ids' && to === 'tier1';
    if (from === 'ids'   && to === 'tier1')   return true;
    if (from === 'tier1' && to === 'tier2')   return activeFlags.tier2;
    if (from === 'tier2' && to === 'tier3')   return activeFlags.tier3;
    if (from === 'tier3' && to === 'warroom') return activeFlags.warroom;
    return false;
  };

  // Layout constants.
  const nodeW = 148;
  const nodeH = 64;
  const gap   = 56;
  const padX  = 16;
  const width = AGENTS.length * nodeW + (AGENTS.length - 1) * gap + padX * 2;
  const height = 140;
  const yMid  = height / 2;

  return (
    <div className="w-full overflow-x-auto">
      <svg viewBox={`0 0 ${width} ${height}`} width="100%" style={{ minWidth: width }} role="img">
        {/* Edges */}
        {AGENTS.slice(0, -1).map((a, i) => {
          const b = AGENTS[i + 1];
          const active = edgeActive(a.id, b.id);
          const x1 = padX + (i + 1) * nodeW + i * gap;
          const x2 = x1 + gap;
          const stroke = active ? C.ember : C.steel;
          return (
            <g key={`edge-${a.id}-${b.id}`}>
              <line
                x1={x1} y1={yMid} x2={x2} y2={yMid}
                stroke={stroke}
                strokeWidth={active ? 1.5 : 1}
                strokeDasharray={active ? '0' : '3 4'}
              />
              {/* Arrowhead */}
              <polygon
                points={`${x2 - 6},${yMid - 4} ${x2},${yMid} ${x2 - 6},${yMid + 4}`}
                fill={stroke}
              />
              {/* Traveling photon */}
              {active && (
                <motion.circle
                  r={3}
                  cy={yMid}
                  fill={C.ember}
                  initial={{ cx: x1 }}
                  animate={{ cx: [x1, x2 - 6] }}
                  transition={{ duration: 1.4, repeat: Infinity, ease: 'easeInOut' }}
                  style={{ filter: `drop-shadow(0 0 4px ${C.ember})` }}
                />
              )}
            </g>
          );
        })}

        {/* Nodes */}
        {AGENTS.map((agent, i) => {
          const x = padX + i * (nodeW + gap);
          const y = yMid - nodeH / 2;
          const col = colorFor(agent.id);
          const active = activeFlags[agent.id];
          return (
            <g key={agent.id} transform={`translate(${x}, ${y})`}>
              {/* Active halo */}
              {active && (
                <rect
                  x={-4} y={-4}
                  width={nodeW + 8} height={nodeH + 8}
                  fill="none"
                  stroke={col.stroke}
                  strokeOpacity={0.18}
                  strokeWidth={6}
                />
              )}
              <rect
                width={nodeW} height={nodeH}
                fill={col.fill}
                stroke={col.stroke}
                strokeWidth={1}
              />
              {/* Corner bracket marks */}
              {(['0,0', `${nodeW},0`, `0,${nodeH}`, `${nodeW},${nodeH}`] as string[]).map((pt, k) => {
                const [px, py] = pt.split(',').map(Number);
                const dx = px === 0 ? 6 : -6;
                const dy = py === 0 ? 6 : -6;
                return (
                  <g key={`${agent.id}-c-${k}`} stroke={col.stroke} strokeWidth={1}>
                    <line x1={px} y1={py} x2={px + dx} y2={py} />
                    <line x1={px} y1={py} x2={px} y2={py + dy} />
                  </g>
                );
              })}
              {/* Label */}
              <text
                x={nodeW / 2}
                y={nodeH / 2 - 4}
                textAnchor="middle"
                fill={col.text}
                fontFamily="Chakra Petch, system-ui, sans-serif"
                fontSize={13}
                fontWeight={700}
                letterSpacing={1.4}
              >
                {agent.label}
              </text>
              <text
                x={nodeW / 2}
                y={nodeH / 2 + 14}
                textAnchor="middle"
                fill={col.text}
                opacity={0.55}
                fontFamily="Instrument Serif, Georgia, serif"
                fontStyle="italic"
                fontSize={12}
              >
                {agent.sub}
              </text>
              {/* Stage index */}
              <text
                x={6} y={12}
                fill={col.text}
                opacity={0.4}
                fontFamily="IBM Plex Mono, ui-monospace, monospace"
                fontSize={9}
                letterSpacing={1.6}
              >
                {`0${i + 1}`}
              </text>
            </g>
          );
        })}

        {/* Bottom baseline axis with stage markers */}
        <line
          x1={padX} y1={height - 18}
          x2={width - padX} y2={height - 18}
          stroke={C.steel}
          strokeWidth={0.5}
        />
        {AGENTS.map((agent, i) => {
          const x = padX + i * (nodeW + gap) + nodeW / 2;
          const active = activeFlags[agent.id];
          return (
            <g key={`axis-${agent.id}`}>
              <line x1={x} y1={height - 22} x2={x} y2={height - 14}
                stroke={active ? C.ember : C.steel} strokeWidth={1} />
              <text
                x={x} y={height - 4}
                textAnchor="middle"
                fill={active ? C.ember : C.fog}
                fontFamily="IBM Plex Mono, ui-monospace, monospace"
                fontSize={9}
                letterSpacing={1.5}
              >
                {active ? 'ACTIVE' : 'IDLE'}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
