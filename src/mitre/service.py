"""
MITRE ATT&CK Query and Correlation Service.

Provides fast lookups and correlation between:
- Machine Learning detection predictions
- SHAP feature importance indicators
- Network flow indicators (e.g. destination port)
- MITRE ATT&CK tactics, techniques, and mitigations
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.api.schemas import MitreMitigation, MitreTechnique


class MitreAttackService:
    """Service to query, search, and correlate network alerts with MITRE ATT&CK."""

    def __init__(self, data_path: Optional[Path] = None):
        if data_path is None:
            data_path = Path(__file__).parent / "attack_data.json"
        self.data_path = Path(data_path)
        self._raw_data: List[Dict[str, Any]] = []
        self._techniques: Dict[str, MitreTechnique] = {}
        self._load_data()

    def _load_data(self) -> None:
        """Loads and validates the MITRE ATT&CK knowledge base from JSON."""
        if not self.data_path.exists():
            raise FileNotFoundError(f"MITRE ATT&CK data file not found at {self.data_path}")

        with open(self.data_path, "r", encoding="utf-8") as f:
            self._raw_data = json.load(f)

        self._techniques = {}
        for item in self._raw_data:
            mitigations = [
                MitreMitigation(
                    id=m["id"],
                    name=m["name"],
                    description=m["description"]
                )
                for m in item.get("mitigations", [])
            ]
            tech = MitreTechnique(
                technique_id=item["technique_id"],
                technique_name=item["technique_name"],
                tactic_id=item["tactic_id"],
                tactic_name=item["tactic_name"],
                description=item["description"],
                url=item.get("url"),
                mitigations=mitigations
            )
            self._techniques[tech.technique_id] = tech

    def get_technique_by_id(self, technique_id: str) -> Optional[MitreTechnique]:
        """Fetch a technique directly by ID (e.g. 'T1071.001')."""
        return self._techniques.get(technique_id.strip().upper())

    def get_all_techniques(self) -> List[MitreTechnique]:
        """Return all mapped MITRE ATT&CK techniques."""
        return list(self._techniques.values())

    def find_by_attack_category(self, attack_category: str) -> List[MitreTechnique]:
        """Find techniques associated with a given attack category name."""
        results: List[MitreTechnique] = []
        cat_lower = attack_category.strip().lower()

        for raw in self._raw_data:
            mapped_categories = [c.lower() for c in raw.get("attack_categories", [])]
            if any(cat_lower in c or c in cat_lower for c in mapped_categories):
                tech = self._techniques.get(raw["technique_id"])
                if tech and tech not in results:
                    results.append(tech)

        return results

    def correlate_alert(
        self,
        attack_type: str,
        shap_feature_names: Optional[List[str]] = None,
        dst_port: Optional[int] = None
    ) -> List[MitreTechnique]:
        """
        Correlates a detected network incident with relevant MITRE ATT&CK techniques.

        Scoring heuristic:
        - Base match on attack_category (+10 pts)
        - Port match (+5 pts)
        - Overlapping SHAP key features (+3 pts per feature match)
        """
        shap_feature_names = [f.lower() for f in (shap_feature_names or [])]
        attack_type_lower = attack_type.strip().lower()
        scored_matches: List[tuple[int, MitreTechnique]] = []

        for raw in self._raw_data:
            score = 0
            # 1. Category match
            mapped_categories = [c.lower() for c in raw.get("attack_categories", [])]
            if any(attack_type_lower in c or c in attack_type_lower for c in mapped_categories):
                score += 10

            # 2. Port match
            relevant_ports = raw.get("relevant_ports", [])
            if dst_port is not None and dst_port in relevant_ports:
                score += 5

            # 3. SHAP features overlap
            relevant_features = [f.lower() for f in raw.get("relevant_features", [])]
            for feature in shap_feature_names:
                if any(rf in feature or feature in rf for rf in relevant_features):
                    score += 3

            if score > 0:
                tech = self._techniques.get(raw["technique_id"])
                if tech:
                    scored_matches.append((score, tech))

        # Sort descending by score
        scored_matches.sort(key=lambda x: x[0], reverse=True)
        return [match[1] for match in scored_matches]

    def search_techniques(self, query: str) -> List[MitreTechnique]:
        """Search techniques by keywords across ID, name, tactic, description, and mitigations."""
        query_lower = query.strip().lower()
        if not query_lower:
            return self.get_all_techniques()

        matches: List[MitreTechnique] = []
        for raw in self._raw_data:
            haystack = (
                f"{raw['technique_id']} {raw['technique_name']} {raw['tactic_name']} "
                f"{raw['description']} {' '.join(m['name'] for m in raw.get('mitigations', []))}"
            ).lower()

            if query_lower in haystack:
                tech = self._techniques.get(raw["technique_id"])
                if tech and tech not in matches:
                    matches.append(tech)

        return matches
