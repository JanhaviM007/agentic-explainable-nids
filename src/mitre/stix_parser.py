"""
STIX 2.1 Parser for Official MITRE ATT&CK Enterprise Bundle.

Extracts techniques, sub-techniques, tactics, mitigations, and relationships
from enterprise-attack.json and caches the structured catalog for fast runtime lookups.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.api.schemas import MitreMitigation, MitreTechnique

logger = logging.getLogger(__name__)

DEFAULT_STIX_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "mitre" / "enterprise-attack.json"
DEFAULT_CATALOG_CACHE = Path(__file__).resolve().parent.parent.parent / "data" / "mitre" / "parsed_catalog.json"
FALLBACK_CATALOG = Path(__file__).resolve().parent / "attack_data.json"


def parse_stix_bundle(stix_file_path: Path) -> List[Dict[str, Any]]:
    """
    Parses an enterprise-attack.json STIX bundle into structured technique dictionaries.

    Args:
        stix_file_path: Path to the raw enterprise-attack.json file.

    Returns:
        List of serializable technique dicts compatible with MitreTechnique.
    """
    logger.info("Parsing MITRE STIX bundle from %s...", stix_file_path)
    with open(stix_file_path, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    objects = bundle.get("objects", [])

    # 1. Extract tactics: shortname -> (tactic_name, tactic_id)
    tactics_map: Dict[str, Tuple[str, str]] = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic":
            shortname = obj.get("x_mitre_shortname", "")
            tactic_name = obj.get("name", "")
            tactic_id = ""
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    tactic_id = ref.get("external_id", "")
                    break
            if shortname:
                tactics_map[shortname.lower()] = (tactic_name, tactic_id)

    # 2. Extract mitigations: STIX id -> MitreMitigation dict
    mitigations_by_stix_id: Dict[str, Dict[str, str]] = {}
    for obj in objects:
        if obj.get("type") == "course-of-action" and not obj.get("x_mitre_deprecated", False):
            m_id = ""
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    m_id = ref.get("external_id", "")
                    break
            if m_id:
                mitigations_by_stix_id[obj["id"]] = {
                    "id": m_id,
                    "name": obj.get("name", "Defensive Mitigation"),
                    "description": obj.get("description", "")
                }

    # 3. Extract mitigation relationships: attack-pattern STIX id -> list of MitreMitigation dicts
    technique_mitigations: Dict[str, List[Dict[str, str]]] = {}
    for obj in objects:
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "mitigates":
            source_ref = obj.get("source_ref")  # course-of-action
            target_ref = obj.get("target_ref")  # attack-pattern
            if source_ref in mitigations_by_stix_id and target_ref:
                technique_mitigations.setdefault(target_ref, []).append(mitigations_by_stix_id[source_ref])

    # 4. Extract techniques & sub-techniques: type == attack-pattern
    parsed_techniques: List[Dict[str, Any]] = []
    seen_ids = set()

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated", False) or obj.get("revoked", False):
            continue

        external_id = ""
        url = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                external_id = ref.get("external_id", "")
                url = ref.get("url", "")
                break

        if not external_id or external_id in seen_ids:
            continue

        seen_ids.add(external_id)

        # Resolve primary tactic
        tactic_name = "Enterprise Attack"
        tactic_id = "TA0000"
        kill_chain = obj.get("kill_chain_phases", [])
        for kc in kill_chain:
            if kc.get("kill_chain_name") == "mitre-attack":
                p_name = kc.get("phase_name", "").lower()
                if p_name in tactics_map:
                    tactic_name, tactic_id = tactics_map[p_name]
                    break

        mitigations = technique_mitigations.get(obj.get("id"), [])

        tech_entry = {
            "technique_id": external_id,
            "technique_name": obj.get("name", "Unknown Technique"),
            "tactic_id": tactic_id,
            "tactic_name": tactic_name,
            "description": obj.get("description", "No description provided."),
            "url": url or f"https://attack.mitre.org/techniques/{external_id.replace('.', '/')}/",
            "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
            "mitigations": mitigations
        }
        parsed_techniques.append(tech_entry)

    logger.info("Successfully parsed %d MITRE ATT&CK techniques from STIX bundle.", len(parsed_techniques))
    return parsed_techniques


def load_mitre_catalog(
    stix_path: Optional[Path] = None,
    cache_path: Optional[Path] = None,
    fallback_path: Optional[Path] = None
) -> Dict[str, MitreTechnique]:
    """
    Loads the MITRE catalog with a 3-tier strategy:
    1. Pre-parsed fast cache (parsed_catalog.json)
    2. Raw STIX bundle (enterprise-attack.json) -> parses and caches
    3. Bundled offline seed (attack_data.json) if STIX is unavailable
    """
    cache = Path(cache_path or DEFAULT_CATALOG_CACHE)
    stix = Path(stix_path or DEFAULT_STIX_PATH)
    fallback = Path(fallback_path or FALLBACK_CATALOG)

    raw_items: List[Dict[str, Any]] = []

    # Strategy 1: Fast Cache
    if cache.exists() and cache.stat().st_size > 10_000:
        try:
            with open(cache, "r", encoding="utf-8") as f:
                raw_items = json.load(f)
            logger.info("Loaded %d techniques from parsed catalog cache at %s", len(raw_items), cache)
        except Exception as e:
            logger.warning("Failed reading catalog cache: %s. Rebuilding...", e)

    # Strategy 2: Raw STIX bundle
    if not raw_items and stix.exists() and stix.stat().st_size > 1_000_000:
        try:
            raw_items = parse_stix_bundle(stix)
            cache.parent.mkdir(parents=True, exist_ok=True)
            with open(cache, "w", encoding="utf-8") as f:
                json.dump(raw_items, f, indent=2)
            logger.info("Saved parsed catalog cache to %s (%d techniques)", cache, len(raw_items))
        except Exception as e:
            logger.warning("Failed parsing STIX bundle: %s. Falling back to bundled catalog...", e)

    # Strategy 3: Bundled fallback
    if not raw_items:
        logger.info("Using bundled offline catalog at %s", fallback)
        if fallback.exists():
            with open(fallback, "r", encoding="utf-8") as f:
                raw_items = json.load(f)

    # Convert to validated Pydantic MitreTechnique instances
    catalog: Dict[str, MitreTechnique] = {}
    for item in raw_items:
        mitigations = [
            MitreMitigation(id=m["id"], name=m["name"], description=m.get("description", ""))
            for m in item.get("mitigations", [])
        ]
        tech = MitreTechnique(
            technique_id=item["technique_id"],
            technique_name=item["technique_name"],
            tactic_id=item["tactic_id"],
            tactic_name=item["tactic_name"],
            description=item.get("description", ""),
            url=item.get("url"),
            mitigations=mitigations
        )
        catalog[tech.technique_id.upper()] = tech

    return catalog
