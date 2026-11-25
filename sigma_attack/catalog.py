"""MITRE ATT&CK catalog helpers used by the Sigma ATT&CK mapper."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Mapping


TECHNIQUE_PATTERN = re.compile(r"^t\d{4}(?:\.\d{3})?$", re.IGNORECASE)
TACTIC_PATTERN = re.compile(r"^[a-z][a-z0-9-]*$", re.IGNORECASE)

# ATT&CK renamed "defense-evasion" to "stealth" in ATT&CK v19. Accept both
# spellings so older Sigma rules and custom rule sets keep mapping correctly.
TACTIC_ALIASES = {
    "defence-evasion": "stealth",
    "defense-evasion": "stealth",
}

TACTIC_ORDER = (
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "stealth",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
    "defense-impairment",
)

DEFAULT_CATALOG_PATH = Path(__file__).resolve().parent / "data" / "attack_catalog.json"


def normalize_technique(value: str) -> str | None:
    """Return a canonical technique ID (``T1059.001``) or ``None``."""

    value = value.strip().lower()
    if value.startswith("attack."):
        value = value[7:]
    if not TECHNIQUE_PATTERN.fullmatch(value):
        return None
    return value.upper()


def normalize_tactic(value: str) -> str | None:
    """Return a canonical ATT&CK tactic short name or ``None``."""

    value = value.strip().lower()
    if value.startswith("attack."):
        value = value[7:]
    value = re.sub(r"[\s_]+", "-", value)
    value = re.sub(r"-+", "-", value).strip("-")
    if not value or not TACTIC_PATTERN.fullmatch(value):
        return None
    return TACTIC_ALIASES.get(value, value)


@dataclass(frozen=True)
class AttackTechnique:
    """A technique from the bundled ATT&CK catalog."""

    technique_id: str
    name: str
    tactics: tuple[str, ...]
    parent_id: str | None = None

    @property
    def is_subtechnique(self) -> bool:
        return "." in self.technique_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "tactics": list(self.tactics),
            "parent": self.parent_id,
        }


class AttackCatalog:
    """Enterprise ATT&CK technique and tactic lookup.

    The catalog is bundled so mapping and reporting are deterministic and do not
    require network access. ``from_stix`` also accepts an official ATT&CK STIX
    bundle, which keeps the data refresh path straightforward.
    """

    def __init__(
        self,
        version: str,
        domain: str,
        tactics: Mapping[str, str],
        techniques: Mapping[str, AttackTechnique],
    ) -> None:
        self.version = version
        self.domain = domain
        self._tactic_names = tuple(dict.fromkeys(tactics.values()))
        self._tactic_by_name = {name: tactic_id for tactic_id, name in tactics.items()}
        self._techniques = dict(techniques)
        self._techniques_by_tactic: dict[str, tuple[str, ...]] = {}
        for tactic in self._tactic_names:
            self._techniques_by_tactic[tactic] = tuple(
                sorted(
                    technique_id
                    for technique_id, technique in self._techniques.items()
                    if tactic in technique.tactics
                )
            )

    @classmethod
    def load(cls, path: str | Path | None = None) -> "AttackCatalog":
        catalog_path = Path(path) if path is not None else DEFAULT_CATALOG_PATH
        with catalog_path.open(encoding="utf-8") as handle:
            return cls.from_dict(json.load(handle))

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AttackCatalog":
        techniques: dict[str, AttackTechnique] = {}
        for raw_id, raw in (data.get("techniques") or {}).items():
            technique_id = normalize_technique(str(raw_id))
            if technique_id is None:
                raise ValueError(f"Invalid ATT&CK technique ID in catalog: {raw_id!r}")
            tactics = []
            for raw_tactic in raw.get("tactics") or []:
                tactic = normalize_tactic(str(raw_tactic))
                if tactic is not None and tactic not in tactics:
                    tactics.append(tactic)
            techniques[technique_id] = AttackTechnique(
                technique_id=technique_id,
                name=str(raw.get("name") or technique_id),
                tactics=tuple(tactics),
                parent_id=raw.get("parent"),
            )
        return cls(
            version=str(data.get("version") or "unknown"),
            domain=str(data.get("domain") or "enterprise-attack"),
            tactics={str(k): str(v) for k, v in (data.get("tactics") or {}).items()},
            techniques=techniques,
        )

    @classmethod
    def from_stix(cls, path: str | Path) -> "AttackCatalog":
        """Build a catalog from an ATT&CK enterprise STIX bundle."""

        with Path(path).open(encoding="utf-8") as handle:
            bundle = json.load(handle)

        tactics: dict[str, str] = {}
        techniques: dict[str, AttackTechnique] = {}
        version = "unknown"

        def external_id(obj: Mapping[str, Any]) -> str | None:
            for reference in obj.get("external_references") or []:
                if reference.get("source_name") == "mitre-attack":
                    value = reference.get("external_id")
                    if value:
                        return str(value)
            return None

        for obj in bundle.get("objects") or []:
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            obj_type = obj.get("type")
            if obj_type == "x-mitre-collection":
                version = str(obj.get("x_mitre_version") or version)
            elif obj_type == "x-mitre-tactic":
                tactic_id = external_id(obj)
                shortname = normalize_tactic(str(obj.get("x_mitre_shortname") or ""))
                if tactic_id and shortname:
                    tactics[tactic_id] = shortname
            elif obj_type == "attack-pattern":
                technique_id = external_id(obj)
                if not technique_id:
                    continue
                canonical_id = normalize_technique(technique_id)
                if canonical_id is None:
                    continue
                technique_tactics = []
                for phase in obj.get("kill_chain_phases") or []:
                    if phase.get("kill_chain_name") != "mitre-attack":
                        continue
                    tactic = normalize_tactic(str(phase.get("phase_name") or ""))
                    if tactic is not None and tactic not in technique_tactics:
                        technique_tactics.append(tactic)
                techniques[canonical_id] = AttackTechnique(
                    technique_id=canonical_id,
                    name=str(obj.get("name") or canonical_id),
                    tactics=tuple(technique_tactics),
                    parent_id=(canonical_id.split(".")[0] if "." in canonical_id else None),
                )
        return cls(version=version, domain="enterprise-attack", tactics=tactics, techniques=techniques)

    @property
    def tactics(self) -> tuple[str, ...]:
        """Tactic short names in canonical kill-chain order."""

        remaining = set(self._tactic_names)
        ordered = [tactic for tactic in TACTIC_ORDER if tactic in remaining]
        ordered.extend(sorted(remaining.difference(ordered)))
        return tuple(ordered)

    @property
    def techniques(self) -> Mapping[str, AttackTechnique]:
        return dict(self._techniques)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable catalog in the bundled data format."""

        return {
            "version": self.version,
            "domain": self.domain,
            "tactics": {
                tactic_id: tactic
                for tactic, tactic_id in sorted(
                    self._tactic_by_name.items(), key=lambda item: item[1]
                )
            },
            "techniques": {
                technique_id: technique.to_dict()
                for technique_id, technique in sorted(self._techniques.items())
            },
        }

    def technique(self, technique_id: str) -> AttackTechnique | None:
        normalized = normalize_technique(technique_id)
        return self._techniques.get(normalized) if normalized else None

    def is_known_technique(self, technique_id: str) -> bool:
        return self.technique(technique_id) is not None

    def is_known_tactic(self, tactic: str) -> bool:
        normalized = normalize_tactic(tactic)
        return normalized in self._tactic_by_name if normalized else False

    def resolve_tactic(self, value: str) -> str | None:
        normalized = normalize_tactic(value)
        if normalized is None or normalized not in self._tactic_by_name:
            return None
        return normalized

    def tactics_for(self, technique_id: str) -> tuple[str, ...]:
        technique = self.technique(technique_id)
        return technique.tactics if technique else ()

    def techniques_for_tactic(self, tactic: str) -> tuple[str, ...]:
        normalized = self.resolve_tactic(tactic)
        if normalized is None:
            return ()
        return self._techniques_by_tactic.get(normalized, ())

    def iter_techniques(self) -> Iterable[AttackTechnique]:
        return (self._techniques[technique_id] for technique_id in sorted(self._techniques))


@lru_cache(maxsize=1)
def get_catalog() -> AttackCatalog:
    """Return the process-wide default catalog."""

    return AttackCatalog.load()

