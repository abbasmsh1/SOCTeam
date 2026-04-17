import json
import os
import logging
import datetime
from typing import List, Dict, Any, Optional
try:
    import chromadb
except ImportError:  # pragma: no cover - optional in unit tests
    chromadb = None

logger = logging.getLogger(__name__)

class VectorMemoryManager:
    """
    Manages long-term SOC incident memory using ChromaDB for high-performance 
    persistent storage and semantic vector search.
    """
    
    def __init__(self, db_path: str = "Implementation/Data/vector_db"):
        """
        Initialize ChromaDB client and collection.
        """
        # Resolve absolute path
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.persist_directory = os.path.join(base_dir, db_path)
        os.makedirs(self.persist_directory, exist_ok=True)

        self.client = None
        self.collection = None
        if chromadb is None:
            logger.warning("chromadb not installed; vector memory disabled")
            return
        
        # Initialize Persistent Client
        self.client = chromadb.PersistentClient(path=self.persist_directory)
        
        # Default embedding function (sentence-transformers is standard but requires extra install)
        # We'll use a lightweight one or the default Chroma one
        self.collection = self.client.get_or_create_collection(
            name="soc_incidents",
            metadata={"description": "SOC Incident Memory for Semantic Retrieval"}
        )
        
        logger.info(f"VectorMemoryManager initialized at {self.persist_directory}")
        
        # Check for legacy migration
        self._migrate_legacy_memory(base_dir)

    def _migrate_legacy_memory(self, base_dir: str):
        """Migrate data from legacy incident_memory.json if it exists."""
        legacy_file = os.path.join(base_dir, "Implementation/Data/incident_memory.json")
        if os.path.exists(legacy_file):
            try:
                with open(legacy_file, 'r') as f:
                    legacy_data = json.load(f)
                
                if legacy_data and self.collection.count() == 0:
                    logger.info(f"Migrating {len(legacy_data)} legacy incidents to Vector DB...")
                    for incident in legacy_data:
                        self.add_incident(incident)
                    
                    # Rename legacy file to avoid re-migration
                    os.rename(legacy_file, legacy_file + ".migrated")
                    logger.info("Legacy memory migration complete.")
            except Exception as e:
                logger.error(f"Migration error: {e}")

    def _prepare_document(self, incident: Dict[str, Any]) -> str:
        """Create a descriptive text document for the incident to be embedded."""
        alert = incident.get("alert_data", {})
        parts = [
            f"Classification: {incident.get('incident_classification', 'Unknown')}",
            f"Severity: {incident.get('final_severity', 'Unknown')}",
            f"Attack: {alert.get('Attack', 'Unknown')}",
            f"Target: {alert.get('DestinationIP', 'N/A')}:{alert.get('DestinationPort', '')}",
            f"Source: {alert.get('SourceIP', 'N/A')}",
            f"Actions: {incident.get('recommended_actions', 'N/A')}",
            f"Description: {str(incident.get('tier1_analysis', {}).get('triage_response', ''))[:500]}"
        ]
        return " | ".join(parts)

    def add_incident(self, incident: Dict[str, Any]):
        """
        Store a new incident in the vector database.
        """
        try:
            if self.collection is None:
                return
            incident_id = incident.get("id", str(datetime.datetime.utcnow().timestamp()))
            document = self._prepare_document(incident)
            
            # Metadata must be simple types for Chroma
            metadata = {
                "severity": incident.get("final_severity", "Unknown"),
                "classification": incident.get("incident_classification", "Unknown"),
                "timestamp": incident.get("timestamp", datetime.datetime.utcnow().isoformat()),
                "attack_type": incident.get("alert_data", {}).get("Attack", "Unknown")
            }
            
            self.collection.add(
                ids=[incident_id],
                documents=[document],
                metadatas=[metadata],
                payloads=[{"full_data": json.dumps(incident)}] if hasattr(self.collection, 'payloads') else None
            )
            
            # Store full JSON separately as Chroma documents are typically for searching
            # In a real system, we might use a hybrid approach (Document + SQL/JSON)
            # For simplicity, we'll store the full data as an attribute if possible or just use a sidecar folder
            full_json_dir = os.path.join(self.persist_directory, "raw_json")
            os.makedirs(full_json_dir, exist_ok=True)
            with open(os.path.join(full_json_dir, f"{incident_id}.json"), 'w') as f:
                json.dump(incident, f, indent=2)
                
            logger.info(f"Incident {incident_id} persisted to Vector DB.")
        except Exception as e:
            logger.error(f"Error adding to Vector DB: {e}")

    def search_similar(self, query_text: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """
        Find top_k similar incidents using vector similarity.
        """
        try:
            if self.collection is None:
                return []
            if self.collection.count() == 0:
                return []

            results = self.collection.query(
                query_texts=[query_text],
                n_results=top_k
            )

            # Reconstruct matches from saved JSON
            matches = []
            full_json_dir = os.path.join(self.persist_directory, "raw_json")
            
            for i, incident_id in enumerate(results['ids'][0]):
                json_path = os.path.join(full_json_dir, f"{incident_id}.json")
                if os.path.exists(json_path):
                    with open(json_path, 'r') as f:
                        match = json.load(f)
                        match['similarity_distance'] = float(results['distances'][0][i])
                        matches.append(match)
            
            return matches
        except Exception as e:
            logger.error(f"Vector search error: {e}")
            return []
