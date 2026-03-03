import { useEffect } from 'react';
import ReactFlow, { 
  Background, 
  Controls, 
  MarkerType,
  Position,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge
} from 'reactflow';
import 'reactflow/dist/style.css';

interface AgentFlowProps {
  latestReport: any;
}

const initialNodes: Node[] = [
  { 
    id: 'ids', 
    position: { x: 0, y: 100 }, 
    data: { label: 'IDS SENSOR' },
    sourcePosition: Position.Right,
    style: { background: '#3b82f6', color: '#fff', border: 'none', borderRadius: '12px', padding: '10px', width: 130 }
  },
  { 
    id: 'tier1', 
    position: { x: 200, y: 100 }, 
    data: { label: 'T1 ANALYST' },
    sourcePosition: Position.Right,
    targetPosition: Position.Left,
    style: { background: '#1e293b', color: '#fff', border: '1px solid #3b82f6', borderRadius: '12px', padding: '10px', width: 130 }
  },
  { 
    id: 'tier2', 
    position: { x: 400, y: 100 }, 
    data: { label: 'T2 ANALYST' },
    sourcePosition: Position.Right,
    targetPosition: Position.Left,
    style: { background: '#1e293b', color: '#fff', border: '1px solid #3b82f6', borderRadius: '12px', padding: '10px', width: 130 }
  },
  { 
    id: 'tier3', 
    position: { x: 600, y: 100 }, 
    data: { label: 'T3 ANALYST' },
    sourcePosition: Position.Right,
    targetPosition: Position.Left,
    style: { background: '#1e293b', color: '#fff', border: '1px solid #3b82f6', borderRadius: '12px', padding: '10px', width: 130 }
  },
  { 
    id: 'warroom', 
    position: { x: 800, y: 100 }, 
    data: { label: 'SECURITY TEAM' },
    targetPosition: Position.Left,
    style: { background: '#1e293b', color: '#fff', border: '1px solid #ef4444', borderRadius: '12px', padding: '10px', width: 130 }
  },
];

const initialEdges: Edge[] = [
  { 
    id: 'e1-2', source: 'ids', target: 'tier1', 
    animated: true, type: 'smoothstep', 
    markerEnd: { type: MarkerType.ArrowClosed, color: '#3b82f6' },
    style: { stroke: '#3b82f6' }
  },
  { 
    id: 'e2-3', source: 'tier1', target: 'tier2', 
    label: 'Escalate', type: 'smoothstep',
    markerEnd: { type: MarkerType.ArrowClosed, color: '#334155' },
    style: { stroke: '#334155' }
  },
  { 
    id: 'e3-4', source: 'tier2', target: 'tier3', 
    type: 'smoothstep',
    markerEnd: { type: MarkerType.ArrowClosed, color: '#334155' },
    style: { stroke: '#334155' }
  },
  { 
    id: 'e4-5', source: 'tier3', target: 'warroom', 
    label: 'Critical', type: 'smoothstep',
    markerEnd: { type: MarkerType.ArrowClosed, color: '#334155' },
    style: { stroke: '#334155' }
  },
];

export default function AgentFlow({ latestReport }: AgentFlowProps) {
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  useEffect(() => {
    if (!latestReport) return;

    // Reset styles
    const newNodes = initialNodes.map(n => ({...n}));
    const newEdges = initialEdges.map(e => ({...e}));

    // Tier 1 is always active if we have a report
    newNodes[1].style = { ...newNodes[1].style, background: '#3b82f6', boxShadow: '0 0 15px #3b82f640' };

    // Tier 2
    if (latestReport.escalated_to_tier2) {
      newNodes[2].style = { ...newNodes[2].style, background: '#8b5cf6', boxShadow: '0 0 15px #8b5cf640', borderColor: '#8b5cf6' };
      // Edge 1-2
      const e2 = newEdges.find(e => e.id === 'e2-3');
      if (e2) {
        e2.animated = true;
        e2.style = { stroke: '#8b5cf6', strokeWidth: 2 };
        e2.markerEnd = { type: MarkerType.ArrowClosed, color: '#8b5cf6' };
      }
    }

    // Tier 3
    if (latestReport.escalated_to_tier3) {
      newNodes[3].style = { ...newNodes[3].style, background: '#f59e0b', boxShadow: '0 0 15px #f59e0b40', borderColor: '#f59e0b' };
        // Edge 2-3
        const e3 = newEdges.find(e => e.id === 'e3-4');
        if (e3) {
          e3.animated = true;
          e3.style = { stroke: '#f59e0b', strokeWidth: 2 };
          e3.markerEnd = { type: MarkerType.ArrowClosed, color: '#f59e0b' };
        }
    }

    // War Room
    if (latestReport.war_room_triggered) {
      newNodes[4].style = { ...newNodes[4].style, background: '#ef4444', boxShadow: '0 0 20px #ef444460', borderColor: '#ef4444' };
        // Edge 3-4
        const e4 = newEdges.find(e => e.id === 'e4-5');
        if (e4) {
          e4.animated = true;
          e4.style = { stroke: '#ef4444', strokeWidth: 2 };
          e4.markerEnd = { type: MarkerType.ArrowClosed, color: '#ef4444' };
        }
    }

    setNodes(newNodes);
    setEdges(newEdges);

  }, [latestReport]);

  return (
    <div className="glass rounded-2xl p-6 h-[500px] w-full mt-6">
      <div className="flex items-center justify-between mb-6">
        <h3 className="text-lg font-bold text-white">Agent Workflow Visualization</h3>
        <div className="flex gap-4">
           {latestReport && (
             <span className="text-xs text-slate-400">
               Displaying path for: <span className="text-white font-mono">{latestReport.name}</span>
             </span>
           )}
        </div>
      </div>
      <div className="h-[380px] bg-background/50 rounded-xl border border-white/5">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          fitView
          nodesConnectable={false}
          nodesDraggable={false}
        >
          <Background color="#ffffff10" />
          <Controls />
        </ReactFlow>
      </div>
    </div>
  );
}
