# System Architecture & Workflows

## 1. Intrusion Detection System (IDS) Architecture

This diagram illustrates the pipeline for processing network traffic through the AI-powered IDS.

```mermaid
graph TD
    %% Styles
    classDef component fill:#e1f5fe,stroke:#01579b,stroke-width:2px,rx:5,ry:5;
    classDef processing fill:#fff3e0,stroke:#e65100,stroke-width:2px,rx:5,ry:5;
    classDef storage fill:#f3e5f5,stroke:#4a148c,stroke-width:2px,shape:cylinder;
    classDef model fill:#e8f5e9,stroke:#1b5e20,stroke-width:2px;

    %% Nodes
    Input[/"Network Input\n(PCAP / Live Packet)"/]:::processing
    
    subgraph "Feature Engineering"
        FE["Flow Extractor\n(CICFlowMeter)"]:::component
        Pre["Preprocessor\n(Cleaning, Scaling)"]:::component
    end
    
    subgraph "AI Core"
        direction TB
        ANN[["ANN Model\n(PyTorch)"]]:::model
        Softmax("Softmax\nProbability"):::processing
    end

    subgraph "Artifacts & Resources"
        Enc["Label Encoders"]:::storage
        Scaler["Standard Scaler"]:::storage
        Weights["Model Weights"]:::storage
    end

    Output[/"Prediction Output\n(Label + Confidence)"/]:::processing
    API["FastAPI / CLI"]:::component

    %% Connections
    Input --> FE
    FE -->|"Raw Flow CSV"| Pre
    
    Enc -.-> Pre
    Scaler -.-> Pre
    
    Pre -->|"Normalized Tensor"| ANN
    Weights -.-> ANN
    
    ANN --> Softmax
    Softmax --> Output
    
    Output --> API
```

## 2. Agentic SOC Workflow (Multi-Agent System)

This diagram represents the orchestration logic implemented in `SOCWorkflow.py` using LangGraph. It shows the hierarchical escalation process from automated triage to human-in-the-loop simulation.

```mermaid
stateDiagram-v2
    direction LR
    
    classDef tier1 fill:#bbdefb,stroke:#0d47a1,stroke-width:2px;
    classDef tier2 fill:#fff9c4,stroke:#fbc02d,stroke-width:2px;
    classDef tier3 fill:#ffccbc,stroke:#bf360c,stroke-width:2px;
    classDef warroom fill:#e1bee7,stroke:#4a148c,stroke-width:2px;
    classDef endstate fill:#c8e6c9,stroke:#1b5e20,stroke-width:2px;

    [*] --> Tier1_Analysis
    
    state "Tier 1: Triage & Assessment" as Tier1_Analysis ::: tier1 {
        [*] --> Enrichment
        Enrichment --> Assessment: GeoIP + Reputation + IDS
        Assessment --> Decision
    }

    Tier1_Analysis --> Finalize: No Escalation\n(Benign/Low Severity)
    Tier1_Analysis --> Tier2_Analysis: **Escalate**\n(High/Critical Severity)

    state "Tier 2: Investigation & Context" as Tier2_Analysis ::: tier2 {
        [*] --> RAG_Retrieval
        RAG_Retrieval --> Analysis: Fetch Similar Incidents
        Analysis --> Validation: Verify Incident
    }

    Tier2_Analysis --> Finalize: Solved / False Positive
    Tier2_Analysis --> Tier3_Analysis: **Escalate**\n(Confirmed Critical Incident)

    state "Tier 3: Response & Strategy" as Tier3_Analysis ::: tier3 {
        [*] --> ThreatModelling
        ThreatModelling --> ResponsePlan: Create Strategy
        ResponsePlan --> CheckScope
    }

    Tier3_Analysis --> Finalize: Standard Incident Response
    Tier3_Analysis --> WarRoom_Simulation: **Trigger War Room**\n(Complex/Novel Threat)

    state "War Room: Attack Simulation" as WarRoom_Simulation ::: warroom {
        [*] --> RedTeam
        RedTeam --> BlueTeam: Attack Simulation
        BlueTeam --> PurpleTeam: Defense Strategy
        PurpleTeam --> [*]: Exercise Analysis
    }

    WarRoom_Simulation --> Finalize

    state "Finalization & Reporting" as Finalize ::: endstate {
        [*] --> GenerateReport
        GenerateReport --> KnowledgeBase: Update Memory
        KnowledgeBase --> [*]
    }

    Finalize --> [*]
```
