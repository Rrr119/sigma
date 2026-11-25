"""Map Sigma rules to MITRE ATT&CK using standard ``attack.*`` tags."""

from __future__ import annotations

import re
from glob import glob
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import yaml

from .catalog import AttackCatalog, get_catalog, normalize_technique


ATTACK_PREFIX = "attack."
SOFTWARE_PATTERN = re.compile(r"^s\d{4}$", re.IGNORECASE)
GROUP_PATTERN = re.compile(r"^g\d{4}$", re.IGNORECASE)
DATA_SOURCE_PATTERN = re.compile(r"^ds\d{4}$", re.IGNORECASE)
MITIGATION_PATTERN = re.compile(r"^m\d{4}$", re.IGNORECASE)
CAMPAIGN_PATTERN = re.compile(r"^c\d{4}$", re.IGNORECASE)


class RuleMappingError(ValueError):
    """Raised when a Sigma rule cannot be loaded or mapped."""


@dataclass(frozen=True)
class AttackMapping:
    """ATT&CK entities referenced by one Sigma rule."""

    rule_id: str | None
    title: str
    path: str | None
    tags: tuple[str, ...] = ()
    techniques: tuple[str, ...] = ()
    explicit_tactics: tuple[str, ...] = ()
    tactics: tuple[str, ...] = ()
    software: tuple[str, ...] = ()
    groups: tuple[str, ...] = ()
    data_sources: tuple[str, ...] = ()
    mitigations: tuple[str, ...] = ()
    campaigns: tuple[str, ...] = ()
    unknown_techniques: tuple[str, ...] = ()
    unknown_attack_tags: tuple[str, ...] = ()

    @property
    def is_mapped(self) -> bool:
        return bool(self.techniques or self.tactics)

    @property
    def has_technique(self) -> bool:
        return bool(self.techniques)

    def rule_ref(self) -> dict[str, str | None]:
        return {"id": self.rule_id, "title": self.title, "path": self.path}

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.rule_id,
            "title": self.title,
            "path": self.path,
            "tags": list(self.tags),
            "techniques": list(self.techniques),
            "explicit_tactics": list(self.explicit_tactics),
            "tactics": list(self.tactics),
            "software": list(self.software),
            "groups": list(self.groups),
            "data_sources": list(self.data_sources),
            "mitigations": list(self.mitigations),
            "campaigns": list(self.campaigns),
            "unknown_techniques": list(self.unknown_techniques),
            "unknown_attack_tags": list(self.unknown_attack_tags),
            "mapped": self.is_mapped,
        }


def _tag_strings(tags: Any) -> Iterable[str]:
    if tags is None:
        return
    if isinstance(tags, str):
        tags = [tags]
    for tag in tags:
        if isinstance(tag, str):
            yield tag
        elif hasattr(tag, "namespace") and hasattr(tag, "name"):
            # pySigma SigmaRuleTag
            yield f"{tag.namespace}.{tag.name}"
        else:
            text = str(tag)
            if text and text != repr(tag):
                yield text


@dataclass
class ParsedAttackTags:
    """ATT&CK entities extracted from one rule's tags."""

    techniques: set[str] = field(default_factory=set)
    explicit_tactics: set[str] = field(default_factory=set)
    software: set[str] = field(default_factory=set)
    groups: set[str] = field(default_factory=set)
    data_sources: set[str] = field(default_factory=set)
    mitigations: set[str] = field(default_factory=set)
    campaigns: set[str] = field(default_factory=set)
    unknown_techniques: set[str] = field(default_factory=set)
    unknown_attack_tags: set[str] = field(default_factory=set)


def parse_attack_tags(
    tags: Any, catalog: AttackCatalog | None = None
) -> ParsedAttackTags:
    """Parse standard Sigma ATT&CK tags.

    The parser accepts both strings and pySigma ``SigmaRuleTag`` objects. Only
    the ``attack`` namespace is interpreted; all other tags are left untouched.
    """

    catalog = catalog or get_catalog()
    parsed = ParsedAttackTags()
    for raw_tag in _tag_strings(tags):
        tag = raw_tag.strip()
        if not tag.lower().startswith(ATTACK_PREFIX):
            continue
        value = tag[len(ATTACK_PREFIX) :].strip().lower()
        if not value:
            parsed.unknown_attack_tags.add(value)
            continue
        technique_id = normalize_technique(value)
        if technique_id is not None:
            parsed.techniques.add(technique_id)
            if not catalog.is_known_technique(technique_id):
                parsed.unknown_techniques.add(technique_id)
            continue
        if SOFTWARE_PATTERN.fullmatch(value):
            parsed.software.add(value.upper())
        elif GROUP_PATTERN.fullmatch(value):
            parsed.groups.add(value.upper())
        elif DATA_SOURCE_PATTERN.fullmatch(value):
            parsed.data_sources.add(value.upper())
        elif MITIGATION_PATTERN.fullmatch(value):
            parsed.mitigations.add(value.upper())
        elif CAMPAIGN_PATTERN.fullmatch(value):
            parsed.campaigns.add(value.upper())
        else:
            tactic = catalog.resolve_tactic(value)
            if tactic is not None:
                parsed.explicit_tactics.add(tactic)
            else:
                parsed.unknown_attack_tags.add(value)
    return parsed


def _load_documents(path: Path) -> list[Mapping[str, Any]]:
    try:
        with path.open(encoding="utf-8") as handle:
            documents = [doc for doc in yaml.safe_load_all(handle) if doc is not None]
    except (OSError, yaml.YAMLError) as exc:
        raise RuleMappingError(f"Unable to load Sigma rule {path}: {exc}") from exc
    if not documents:
        raise RuleMappingError(f"Sigma rule {path} is empty")
    for document in documents:
        if not isinstance(document, Mapping):
            raise RuleMappingError(f"Sigma rule {path} must contain a YAML mapping")
    return documents


def _mapping_from_data(
    data: Mapping[str, Any],
    path: str | None,
    catalog: AttackCatalog,
) -> AttackMapping:
    tags = tuple(str(tag) for tag in _tag_strings(data.get("tags") or []))
    parsed = parse_attack_tags(tags, catalog=catalog)
    derived_tactics: set[str] = set()
    for technique_id in parsed.techniques:
        derived_tactics.update(catalog.tactics_for(technique_id))

    return AttackMapping(
        rule_id=str(data["id"]) if data.get("id") is not None else None,
        title=str(data.get("title") or (Path(path).stem if path else "")),
        path=path,
        tags=tags,
        techniques=tuple(sorted(parsed.techniques)),
        explicit_tactics=tuple(sorted(parsed.explicit_tactics)),
        tactics=tuple(sorted(parsed.explicit_tactics | derived_tactics)),
        software=tuple(sorted(parsed.software)),
        groups=tuple(sorted(parsed.groups)),
        data_sources=tuple(sorted(parsed.data_sources)),
        mitigations=tuple(sorted(parsed.mitigations)),
        campaigns=tuple(sorted(parsed.campaigns)),
        unknown_techniques=tuple(sorted(parsed.unknown_techniques)),
        unknown_attack_tags=tuple(sorted(parsed.unknown_attack_tags)),
    )


def map_rule(
    rule: Any,
    path: str | Path | None = None,
    catalog: AttackCatalog | None = None,
) -> AttackMapping:
    """Map a Sigma rule to ATT&CK.

    ``rule`` may be a mapping (for example ``yaml.safe_load`` output), a pySigma
    ``SigmaRule`` instance, or a path to a Sigma YAML file. The function does
    not modify the input rule and only reads the standard ``tags`` metadata, so
    it is safe to use alongside pySigma converters.
    """

    catalog = catalog or get_catalog()
    if isinstance(rule, (str, Path)):
        rule_path = Path(rule)
        documents = _load_documents(rule_path)
        return _mapping_from_data(documents[0], str(rule_path), catalog)

    if isinstance(rule, Mapping):
        label = str(path) if path is not None else None
        return _mapping_from_data(rule, label, catalog)

    if hasattr(rule, "tags"):
        data = {
            "id": getattr(rule, "id", None),
            "title": getattr(rule, "title", None),
            "tags": getattr(rule, "tags", None),
        }
        label = str(path) if path is not None else None
        return _mapping_from_data(data, label, catalog)

    raise TypeError("rule must be a mapping, a pySigma SigmaRule, or a YAML file path")


def iter_rule_files(
    paths: str | Path | Sequence[str | Path],
    file_pattern: str = "*.yml",
) -> Iterable[Path]:
    """Yield rule files from files and directories in deterministic order."""

    if isinstance(paths, (str, Path)):
        paths = [paths]
    seen: set[Path] = set()
    for raw_path in paths:
        path = Path(raw_path)
        if not path.exists():
            matches = [Path(match) for match in glob(str(raw_path), recursive=True)]
            if not matches:
                raise FileNotFoundError(f"Rule path does not exist: {path}")
            candidates = matches
        else:
            candidates = [path] if path.is_file() else path.rglob(file_pattern)
        for candidate in sorted(candidates):
            if candidate.is_file() and candidate not in seen:
                seen.add(candidate)
                yield candidate


def map_rules(
    paths: str | Path | Sequence[str | Path],
    file_pattern: str = "*.yml",
    catalog: AttackCatalog | None = None,
) -> tuple[AttackMapping, ...]:
    """Map all Sigma YAML documents below one or more files/directories."""

    catalog = catalog or get_catalog()
    mappings: list[AttackMapping] = []
    for rule_path in iter_rule_files(paths, file_pattern=file_pattern):
        documents = _load_documents(rule_path)
        for index, document in enumerate(documents, 1):
            label = str(rule_path)
            if len(documents) > 1:
                label = f"{label}#{index}"
            mappings.append(_mapping_from_data(document, label, catalog))
    return tuple(mappings)


def attack_tags_for(mapping: AttackMapping) -> tuple[str, ...]:
    """Return canonical ``attack.*`` tags for an existing mapping."""

    return tuple(
        sorted(
            [f"attack.{technique.lower()}" for technique in mapping.techniques]
            + [f"attack.{tactic}" for tactic in mapping.tactics]
        )
    )

