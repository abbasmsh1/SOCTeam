export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface IDSPrediction {
  flow_index: number;
  predicted_label: string;
  predicted_index: number;
  confidence: number;
}

export interface LiveFlow {
  timestamp: string;
  SourceIP: string;
  DestinationIP: string;
  SourcePort: number;
  DestinationPort: number;
  Protocol: number;
  Attack: string;
  Severity: Severity;
  confidence: number;
}

export interface AgentStatus {
  id: string;
  name: string;
  status: "idle" | "busy" | "error";
  lastAction?: string;
}

export interface Report {
  id: string;
  name: string;
  created_at: string;
}
