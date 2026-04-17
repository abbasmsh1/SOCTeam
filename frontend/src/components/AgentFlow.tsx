/**
 * AgentFlow.tsx
 * =============
 * Visualizes the SOC agent escalation pipeline as a horizontal node graph:
 *   IDS SENSOR → T1 ANALYST → T2 ANALYST → T3 ANALYST → SECURITY TEAM
 *
 * Active nodes light up based on escalation data from the latest report.
 * Edges pulse when a flow was escalated between two adjacent tiers.
 */

/** Props for the AgentFlow component. */
interface AgentFlowProps {
  latestReport: any;
}

/**
 * Pipeline stages (left-to-right order).
 * `color` is the default (inactive) background; active colors are
 * computed dynamically in `getNodeColor`.
 */
const AGENTS = [
  { id: 'ids',     label: 'IDS SENSOR',    color: '#3b82f6' },
  { id: 'tier1',   label: 'T1 ANALYST',    color: '#1e293b' },
  { id: 'tier2',   label: 'T2 ANALYST',    color: '#1e293b' },
  { id: 'tier3',   label: 'T3 ANALYST',    color: '#1e293b' },
  { id: 'warroom', label: 'SECURITY TEAM', color: '#1e293b' },
];

/** Color mapping for each escalation level. */
const COLOR = {
  BLUE:    '#3b82f6',  // IDS / Tier 1
  PURPLE:  '#8b5cf6',  // Tier 2
  AMBER:   '#f59e0b',  // Tier 3
  RED:     '#ef4444',  // War Room / Security Team
  DARK:    '#1e293b',  // Inactive node
  BORDER:  '#334155',  // Inactive border
  EDGE_ON: '#60a5fa',  // Active edge
  EDGE_OFF:'#334155',  // Inactive edge
} as const;

export default function AgentFlow({ latestReport }: AgentFlowProps) {

  /**
   * Determines the background color for a pipeline node based on
   * escalation flags in the latest report.
   */
  const getNodeColor = (id: string): string => {
    if (!latestReport) return id === 'ids' ? COLOR.BLUE : COLOR.DARK;

    if (id === 'ids')                                        return COLOR.BLUE;
    if (id === 'tier1')                                      return COLOR.BLUE;
    if (id === 'tier2'   && latestReport.escalated_to_tier2) return COLOR.PURPLE;
    if (id === 'tier3'   && latestReport.escalated_to_tier3) return COLOR.AMBER;
    if (id === 'warroom' && latestReport.war_room_triggered) return COLOR.RED;
    return COLOR.DARK;
  };

  /** Returns the border color – matches the node's active color or falls back to inactive. */
  const getBorderColor = (id: string): string => {
    const c = getNodeColor(id);
    return c !== COLOR.DARK ? c : COLOR.BORDER;
  };

  /** Adds a glow effect to active nodes; inactive nodes have no glow. */
  const getGlow = (id: string): string => {
    const c = getNodeColor(id);
    return c === COLOR.DARK ? 'none' : `0 0 15px ${c}60`;
  };

  /** Checks whether the edge between two adjacent nodes should be highlighted. */
  const isEdgeActive = (from: string, to: string): boolean => {
    if (!latestReport) return false;
    if (from === 'ids'   && to === 'tier1')   return true;
    if (from === 'tier1' && to === 'tier2')   return !!latestReport.escalated_to_tier2;
    if (from === 'tier2' && to === 'tier3')   return !!latestReport.escalated_to_tier3;
    if (from === 'tier3' && to === 'warroom') return !!latestReport.war_room_triggered;
    return false;
  };

  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 0, padding: '2rem 0', overflowX: 'auto' }}>
      {AGENTS.map((agent, idx) => (
        <div key={agent.id} style={{ display: 'flex', alignItems: 'center' }}>

          {/* Pipeline Node */}
          <div style={{
            width: 120,
            padding: '12px 8px',
            textAlign: 'center',
            background: getNodeColor(agent.id),
            border: `1px solid ${getBorderColor(agent.id)}`,
            boxShadow: getGlow(agent.id),
            transition: 'all 0.4s ease',
            color: '#fff',
            fontSize: 10,
            fontFamily: 'monospace',
            fontWeight: 700,
            letterSpacing: '0.08em',
            flexShrink: 0,
          }}>
            {agent.label}
          </div>

          {/* Arrow connector between nodes */}
          {idx < AGENTS.length - 1 && (() => {
            const nextAgent = AGENTS[idx + 1];
            const active = isEdgeActive(agent.id, nextAgent.id);
            return (
              <div style={{ display: 'flex', alignItems: 'center', width: 40, flexShrink: 0 }}>
                {/* Horizontal line */}
                <div style={{
                  flex: 1,
                  height: 2,
                  background: active ? COLOR.EDGE_ON : COLOR.EDGE_OFF,
                  transition: 'background 0.3s',
                  animation: active ? 'pulse 1.5s infinite' : 'none',
                }} />
                {/* Arrowhead (CSS triangle) */}
                <div style={{
                  width: 0,
                  height: 0,
                  borderTop: '5px solid transparent',
                  borderBottom: '5px solid transparent',
                  borderLeft: `6px solid ${active ? COLOR.EDGE_ON : COLOR.EDGE_OFF}`,
                  transition: 'border-color 0.3s',
                }} />
              </div>
            );
          })()}
        </div>
      ))}

      {/* Keyframe animation for pulsing active edges */}
      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.4; }
        }
      `}</style>
    </div>
  );
}
