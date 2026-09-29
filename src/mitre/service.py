"""
Refactored MITRE ATT&CK Query and Correlation Service.

Integrates the official MITRE Enterprise ATT&CK STIX catalog (690+ techniques),
dataset label mappings (src/mitre/label_mapping.json), and relevance-scored search.
Includes offline fallback to bundled attack_data.json.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.api.schemas import MitreTechnique
from src.mitre.stix_parser import load_mitre_catalog

logger = logging.getLogger(__name__)

DEFAULT_LABEL_MAPPING = Path(__file__).resolve().parent / "label_mapping.json"


class MitreAttackService:
    """Enterprise-grade service to query, search, and correlate network alerts with MITRE ATT&CK."""

    def __init__(
        self,
        stix_path: Optional[Path] = None,
        cache_path: Optional[Path] = None,
        fallback_path: Optional[Path] = None,
        label_mapping_path: Optional[Path] = None,
    ):
        self._label_mapping_path = Path(label_mapping_path or DEFAULT_LABEL_MAPPING)
        self._techniques: Dict[str, MitreTechnique] = {}
        self._label_mapping: Dict[str, Dict[str, Any]] = {}

        # 1. Load catalog using multi-tier strategy (parsed cache -> STIX -> fallback)
        self._load_catalog(stix_path, cache_path, fallback_path)

        # 2. Load label mapping
        self._load_label_mapping()

    def _load_catalog(
        self,
        stix_path: Optional[Path] = None,
        cache_path: Optional[Path] = None,
        fallback_path: Optional[Path] = None
    ) -> None:
        """Loads techniques from STIX cache or fallback file."""
        self._techniques = load_mitre_catalog(
            stix_path=stix_path,
            cache_path=cache_path,
            fallback_path=fallback_path
        )
        logger.info("MitreAttackService ready with %d techniques.", len(self._techniques))

    def _load_label_mapping(self) -> None:
        """Loads label-to-technique associations from label_mapping.json."""
        if self._label_mapping_path.exists():
            with open(self._label_mapping_path, "r", encoding="utf-8") as f:
                self._label_mapping = json.load(f)
            logger.info("Loaded %d dataset label mappings.", len(self._label_mapping))
        else:
            logger.warning("label_mapping.json not found at %s.", self._label_mapping_path)
            self._label_mapping = {}

    def get_technique_by_id(self, technique_id: str) -> Optional[MitreTechnique]:
        """
        Direct lookup of a MITRE technique by ID (e.g. 'T1071.001' or 't1071.001').
        """
        if not technique_id:
            return None
        return self._techniques.get(technique_id.strip().upper())

    def get_all_techniques(self) -> List[MitreTechnique]:
        """Return all loaded MITRE ATT&CK techniques."""
        return list(self._techniques.values())

    def get_techniques_for_label(self, label: str) -> List[MitreTechnique]:
        """
        Lookup MITRE techniques mapped to a dataset label (e.g. 'C2_Beaconing', 'PortScan').
        """
        clean_label = label.strip()
        mapping = self._label_mapping.get(clean_label)

        # Fallback to case-insensitive match
        if not mapping:
            for k, v in self._label_mapping.items():
                if k.lower() == clean_label.lower():
                    mapping = v
                    break

        if not mapping:
            return []

        matched: List[MitreTechnique] = []
        for tid in mapping.get("technique_ids", []):
            tech = self.get_technique_by_id(tid)
            if tech:
                matched.append(tech)

        return matched

    def find_by_attack_category(self, attack_category: str) -> List[MitreTechnique]:
        """
        Finds techniques matching an attack category name across mappings and catalog.
        Maintains backward compatibility with Phase 1 callers.
        """
        # Try label mapping first
        from_label = self.get_techniques_for_label(attack_category)
        if from_label:
            return from_label

        # Otherwise search by keywords in category name
        return self.search_techniques(attack_category, limit=5)

    def correlate_alert(
        self,
        attack_type: str,
        shap_feature_names: Optional[List[str]] = None,
        dst_port: Optional[int] = None
    ) -> List[MitreTechnique]:
        """
        Correlates a detected network incident with relevant MITRE ATT&CK techniques.

        Scoring heuristic:
        - Exact label mapping match: +30 pts
        - Port match:
          - Port 53 -> T1071.004, T1048 (+20 pts)
          - Port 445/139 -> T1021.002, T1569.002, T1047 (+20 pts)
          - Port 443/80 -> T1071.001, T1573 (+15 pts)
          - Port 22 -> T1021.004, T1110 (+15 pts)
        - SHAP feature keywords match in technique description/name: +5 pts per match
        """
        scored_matches: Dict[str, tuple[int, MitreTechnique]] = {}

        # 1. Base matches from label mapping
        label_techniques = self.get_techniques_for_label(attack_type)
        for tech in label_techniques:
            scored_matches[tech.technique_id] = (30, tech)

        # 2. Port-specific heuristic boosts
        port_rules: Dict[int, List[str]] = {
            53: ["T1071.004", "T1048.003", "T1048"],
            445: ["T1021.002", "T1569.002", "T1047"],
            139: ["T1021.002", "T1569.002"],
            443: ["T1071.001", "T1573.002", "T1573"],
            80: ["T1071.001", "T1190"],
            8080: ["T1071.001", "T1190"],
            8443: ["T1071.001", "T1573.002"],
            22: ["T1021.004", "T1110"],
            5985: ["T1059.001", "T1021.006"],
            135: ["T1047", "T1021.002"],
        }

        if dst_port in port_rules:
            for tid in port_rules[dst_port]:
                tech = self.get_technique_by_id(tid)
                if tech:
                    curr_score = scored_matches.get(tech.technique_id, (0, tech))[0]
                    scored_matches[tech.technique_id] = (curr_score + 20, tech)

        # 3. SHAP feature keyword relevance
        feature_keywords = [f.lower().replace("_", " ") for f in (shap_feature_names or [])]
        for tid, (score, tech) in list(scored_matches.items()):
            tech_text = f"{tech.technique_name} {tech.description}".lower()
            bonus = 0
            for kw in feature_keywords:
                # check individual key terms like iat, beacon, duration, length, packets
                for term in kw.split():
                    if len(term) > 3 and term in tech_text:
                        bonus += 5
            if bonus > 0:
                scored_matches[tid] = (score + bonus, tech)

        # Fallback if nothing matched yet
        if not scored_matches:
            fallback_techs = self.search_techniques(attack_type, limit=3)
            return fallback_techs

        # Sort descending by score
        sorted_list = sorted(scored_matches.values(), key=lambda x: x[0], reverse=True)
        return [match[1] for match in sorted_list]

    def search_techniques(self, query: str, limit: int = 15) -> List[MitreTechnique]:
        """
        Relevance-scored search across technique IDs, names, tactics, and descriptions.

        Scoring:
        - Exact technique ID match: +100
        - Prefix ID match (e.g. 'T1071' matches 'T1071.001'): +60
        - Technique name exact match: +40
        - Technique name word match: +20
        - Tactic match: +15
        - Description word match: +2
        """
        clean_query = query.strip().lower()
        if not clean_query:
            return list(self._techniques.values())[:limit]

        query_tokens = [t for t in clean_query.split() if len(t) > 2]
        scored_results: List[tuple[int, MitreTechnique]] = []

        for tid, tech in self._techniques.items():
            score = 0
            tid_lower = tid.lower()
            name_lower = tech.technique_name.lower()
            tactic_lower = tech.tactic_name.lower()
            desc_lower = tech.description.lower()

            # ID scoring
            if clean_query == tid_lower:
                score += 100
            elif tid_lower.startswith(clean_query):
                score += 60

            # Name scoring
            if clean_query == name_lower:
                score += 40
            elif clean_query in name_lower:
                score += 25

            # Tactic scoring
            if clean_query in tactic_lower:
                score += 15

            # Token scoring
            for token in query_tokens:
                if token in name_lower:
                    score += 15
                if token in desc_lower:
                    score += 2
                if any(token in m.name.lower() for m in tech.mitigations):
                    score += 5

            if score > 0:
                scored_results.append((score, tech))

        scored_results.sort(key=lambda x: x[0], reverse=True)
        return [item[1] for item in scored_results[:limit]]
