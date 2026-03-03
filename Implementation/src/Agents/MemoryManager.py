import json
import os
import numpy as np
from typing import List, Dict, Any
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

class MemoryManager:
    """
    Manages long-term memory of SOC incidents using JSON storage and TF-IDF semantic search.
    """
    def __init__(self, memory_file: str = "incident_memory.json"):
        # Resolve absolute path relative to this file
        base_dir = os.path.dirname(os.path.abspath(__file__))
        # Go up to Implementation/Data or similar. Let's put it in the same dir as Agents for now or Data if exists.
        # Ideally: e:\IMT\2nd Sem\Project\Implementation\Data\incident_memory.json
        data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(base_dir))), "Implementation", "Data")
        if not os.path.exists(data_dir):
            os.makedirs(data_dir, exist_ok=True)
            
        self.memory_file = os.path.join(data_dir, memory_file)
        self.incidents = self._load_memory()
        self.vectorizer = TfidfVectorizer(stop_words='english')
        self.vectors = None
        self._build_index()

    def _load_memory(self) -> List[Dict[str, Any]]:
        """Load incidents from JSON file."""
        if os.path.exists(self.memory_file):
            try:
                with open(self.memory_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                return []
        return []

    def _save_memory(self):
        """Save incidents to JSON file."""
        with open(self.memory_file, 'w') as f:
            json.dump(self.incidents, f, indent=4)

    def _build_index(self):
        """Rebuild TF-IDF index from incident descriptions."""
        if not self.incidents:
            return

        # Create a text representation for each incident combining relevant fields
        corpus = []
        for inc in self.incidents:
            text = f"{inc.get('incident_classification', '')} {inc.get('final_severity', '')} {str(inc.get('alert_data', ''))}"
            corpus.append(text)
        
        if corpus:
            self.vectors = self.vectorizer.fit_transform(corpus)

    def add_incident(self, incident: Dict[str, Any]):
        """Add a new incident to memory and update index."""
        # Only add if it has meaningful data
        if not incident:
            return

        self.incidents.append(incident)
        self._save_memory()
        self._build_index()

    def search_similar(self, query_text: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """
        Search for similar past incidents using TF-IDF cosine similarity.
        """
        if not self.incidents or self.vectors is None:
            return []

        # Transform query
        query_vec = self.vectorizer.transform([query_text])
        
        # Calculate similarity
        similarities = cosine_similarity(query_vec, self.vectors).flatten()
        
        # Get top k indices
        top_indices = similarities.argsort()[-top_k:][::-1]
        
        results = []
        for idx in top_indices:
            score = similarities[idx]
            if score > 0.1: # Filter out very low relevance
                match = self.incidents[idx].copy()
                match['similarity_score'] = float(score)
                results.append(match)
                
        return results
