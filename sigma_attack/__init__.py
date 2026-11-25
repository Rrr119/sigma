"""Automatic MITRE ATT&CK mapping and coverage for Sigma rules."""

from .catalog import AttackCatalog, AttackTechnique, get_catalog
from .coverage import CoverageReport, TacticCoverage, TechniqueCoverage, build_coverage
from .mapping import (
    AttackMapping,
    ParsedAttackTags,
    RuleMappingError,
    attack_tags_for,
    iter_rule_files,
    map_rule,
    map_rules,
    parse_attack_tags,
)

__all__ = [
    "AttackCatalog",
    "AttackMapping",
    "AttackTechnique",
    "CoverageReport",
    "ParsedAttackTags",
    "RuleMappingError",
    "TacticCoverage",
    "TechniqueCoverage",
    "attack_tags_for",
    "build_coverage",
    "get_catalog",
    "iter_rule_files",
    "map_rule",
    "map_rules",
    "parse_attack_tags",
]

__version__ = "0.1.0"

