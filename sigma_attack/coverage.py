"""MITRE ATT&CK coverage reports generated from Sigma rule mappings."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .catalog import AttackCatalog, get_catalog
from .mapping import AttackMapping


def _percentage(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return round(numerator * 100.0 / denominator, 2)


@dataclass(frozen=True)
class TechniqueCoverage:
    technique_id: str
    name: str
    tactics: tuple[str, ...]
    mappings: tuple[AttackMapping, ...]
    known: bool = True

    @property
    def rule_count(self) -> int:
        return len(self.mappings)

    def to_dict(self, include_rule_refs: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "name": self.name,
            "tactics": list(self.tactics),
            "known": self.known,
            "rule_count": self.rule_count,
        }
        if include_rule_refs:
            data["rules"] = [mapping.rule_ref() for mapping in self.mappings]
        return data


@dataclass(frozen=True)
class TacticCoverage:
    tactic: str
    catalog_techniques: tuple[str, ...]
    covered_techniques: tuple[str, ...]
    rule_count: int

    @property
    def uncovered_techniques(self) -> tuple[str, ...]:
        covered = set(self.covered_techniques)
        return tuple(
            technique
            for technique in self.catalog_techniques
            if technique not in covered
        )

    @property
    def coverage_percent(self) -> float:
        return _percentage(len(self.covered_techniques), len(self.catalog_techniques))

    def to_dict(self) -> dict[str, Any]:
        return {
            "catalog_techniques": len(self.catalog_techniques),
            "covered_techniques": len(self.covered_techniques),
            "coverage_percent": self.coverage_percent,
            "rule_count": self.rule_count,
            "techniques": list(self.covered_techniques),
            "uncovered_techniques": list(self.uncovered_techniques),
        }


class CoverageReport:
    """Aggregated ATT&CK coverage for a set of Sigma rules."""

    def __init__(
        self,
        mappings: Iterable[AttackMapping],
        catalog: AttackCatalog | None = None,
    ) -> None:
        self.catalog = catalog or get_catalog()
        self.mappings = tuple(mappings)

        technique_mappings: dict[str, list[AttackMapping]] = defaultdict(list)
        for mapping in self.mappings:
            for technique_id in mapping.techniques:
                technique_mappings[technique_id].append(mapping)

        self._by_technique: dict[str, TechniqueCoverage] = {}
        for technique_id in sorted(technique_mappings):
            technique = self.catalog.technique(technique_id)
            self._by_technique[technique_id] = TechniqueCoverage(
                technique_id=technique_id,
                name=technique.name if technique else technique_id,
                tactics=technique.tactics if technique else (),
                mappings=tuple(technique_mappings[technique_id]),
                known=technique is not None,
            )

        tactic_rule_counts: Counter[str] = Counter()
        for mapping in self.mappings:
            tactic_rule_counts.update(set(mapping.tactics))

        self._by_tactic: dict[str, TacticCoverage] = {}
        for tactic in self.catalog.tactics:
            catalog_techniques = self.catalog.techniques_for_tactic(tactic)
            covered = tuple(
                technique_id
                for technique_id in catalog_techniques
                if technique_id in self._by_technique
            )
            self._by_tactic[tactic] = TacticCoverage(
                tactic=tactic,
                catalog_techniques=catalog_techniques,
                covered_techniques=covered,
                rule_count=tactic_rule_counts.get(tactic, 0),
            )

    @property
    def by_technique(self) -> Mapping[str, TechniqueCoverage]:
        return dict(self._by_technique)

    @property
    def by_tactic(self) -> Mapping[str, TacticCoverage]:
        return dict(self._by_tactic)

    @property
    def rules_with_techniques(self) -> tuple[AttackMapping, ...]:
        return tuple(mapping for mapping in self.mappings if mapping.techniques)

    @property
    def rules_without_technique(self) -> tuple[AttackMapping, ...]:
        return tuple(mapping for mapping in self.mappings if not mapping.techniques)

    @property
    def rules_without_any_attack_mapping(self) -> tuple[AttackMapping, ...]:
        return tuple(mapping for mapping in self.mappings if not mapping.is_mapped)

    @property
    def unknown_techniques(self) -> tuple[str, ...]:
        return tuple(
            technique_id
            for technique_id, coverage in self._by_technique.items()
            if not coverage.known
        )

    @property
    def unknown_attack_tags(self) -> Mapping[str, tuple[AttackMapping, ...]]:
        references: dict[str, list[AttackMapping]] = defaultdict(list)
        for mapping in self.mappings:
            for tag in mapping.unknown_attack_tags:
                references[tag].append(mapping)
        return {tag: tuple(references[tag]) for tag in sorted(references)}

    def summary(self) -> dict[str, Any]:
        total = len(self.mappings)
        with_technique = len(self.rules_with_techniques)
        with_tactic = sum(1 for mapping in self.mappings if mapping.tactics)
        catalog_techniques = len(self.catalog.techniques)
        return {
            "rules_total": total,
            "rules_with_attack_technique": with_technique,
            "rules_with_attack_tactic": with_tactic,
            "rules_without_technique": len(self.rules_without_technique),
            "rules_without_any_attack_mapping": len(self.rules_without_any_attack_mapping),
            "rule_coverage_percent": _percentage(with_technique, total),
            "techniques_covered": len(self._by_technique),
            "techniques_in_catalog": catalog_techniques,
            "technique_coverage_percent": _percentage(
                len(self._by_technique), catalog_techniques
            ),
            "techniques_unknown": len(self.unknown_techniques),
            "unknown_attack_tags": len(self.unknown_attack_tags),
        }

    def to_dict(self, include_rule_refs: bool = True) -> dict[str, Any]:
        summary = self.summary()
        return {
            "attack_version": self.catalog.version,
            "domain": self.catalog.domain,
            "summary": summary,
            "by_tactic": {
                tactic: coverage.to_dict()
                for tactic, coverage in self._by_tactic.items()
            },
            "by_technique": {
                technique_id: coverage.to_dict(include_rule_refs=include_rule_refs)
                for technique_id, coverage in self._by_technique.items()
            },
            "unknown_techniques": list(self.unknown_techniques),
            "unknown_attack_tags": [
                {
                    "tag": f"attack.{tag}",
                    "rule_count": len(mappings),
                    "rules": [mapping.rule_ref() for mapping in mappings],
                }
                for tag, mappings in self.unknown_attack_tags.items()
            ],
            "rules_without_technique": [
                mapping.rule_ref() for mapping in self.rules_without_technique
            ],
        }

    def to_markdown(
        self,
        max_unmapped: int = 50,
        top_techniques: int = 20,
        uncovered_examples: int = 12,
        include_rule_refs: bool = True,
    ) -> str:
        summary = self.summary()
        lines = [
            "# MITRE ATT&CK Coverage Report",
            "",
            f"- ATT&CK version: {self.catalog.version}",
            f"- Rules scanned: {summary['rules_total']}",
            (
                "- Rules with ATT&CK techniques: "
                f"{summary['rules_with_attack_technique']} "
                f"({summary['rule_coverage_percent']:.2f}%)"
            ),
            f"- Rules with ATT&CK tactics: {summary['rules_with_attack_tactic']}",
            f"- Rules without a technique: {summary['rules_without_technique']}",
            (
                "- Techniques covered: "
                f"{summary['techniques_covered']}/{summary['techniques_in_catalog']} "
                f"({summary['technique_coverage_percent']:.2f}%)"
            ),
            "",
            "## Coverage by tactic",
            "",
            "| Tactic | Covered | Total | Coverage | Rules |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
        for coverage in self._by_tactic.values():
            lines.append(
                f"| {coverage.tactic} | {len(coverage.covered_techniques)} | "
                f"{len(coverage.catalog_techniques)} | "
                f"{coverage.coverage_percent:.2f}% | {coverage.rule_count} |"
            )

        ranked = sorted(
            self._by_technique.values(),
            key=lambda coverage: (-coverage.rule_count, coverage.technique_id),
        )
        if top_techniques > 0 and ranked:
            lines.extend(
                [
                    "",
                    "## Top covered techniques",
                    "",
                    "| Technique | Name | Tactic | Rules |",
                    "| --- | --- | --- | ---: |",
                ]
            )
            for coverage in ranked[:top_techniques]:
                tactics = ", ".join(coverage.tactics) or "unknown"
                lines.append(
                    f"| {coverage.technique_id} | {self._escape(coverage.name)} | "
                    f"{tactics} | {coverage.rule_count} |"
                )

        uncovered = [coverage for coverage in self._by_tactic.values() if coverage.uncovered_techniques]
        if uncovered_examples > 0 and uncovered:
            lines.extend(
                [
                    "",
                    "## Uncovered techniques by tactic",
                    "",
                    "| Tactic | Uncovered | Examples |",
                    "| --- | ---: | --- |",
                ]
            )
            for coverage in uncovered:
                examples = ", ".join(
                    coverage.uncovered_techniques[:uncovered_examples]
                )
                if len(coverage.uncovered_techniques) > uncovered_examples:
                    examples += ", ..."
                lines.append(
                    f"| {coverage.tactic} | "
                    f"{len(coverage.uncovered_techniques)} | {examples} |"
                )

        if include_rule_refs and self.rules_without_technique and max_unmapped > 0:
            lines.extend(["", "## Rules without a technique", ""])
            for mapping in self.rules_without_technique[:max_unmapped]:
                label = mapping.path or mapping.title or mapping.rule_id or "<unknown rule>"
                if mapping.title and mapping.path:
                    label = f"{label} ({mapping.title})"
                lines.append(f"- `{label}`")
            remaining = len(self.rules_without_technique) - min(
                max_unmapped, len(self.rules_without_technique)
            )
            if remaining > 0:
                lines.append(f"- ... and {remaining} more")

        if self.unknown_attack_tags:
            lines.extend(["", "## Unknown ATT&CK tags", ""])
            for tag, mappings in self.unknown_attack_tags.items():
                lines.append(f"- `attack.{tag}` ({len(mappings)} rules)")

        lines.append("")
        return "\n".join(lines)

    def to_navigator_layer(
        self,
        name: str = "Sigma ATT&CK Coverage",
        description: str | None = None,
        min_score: int = 0,
        max_score: int | None = None,
        min_color: str = "#ffffff00",
        max_color: str = "#ff0000",
        include_subtechniques: bool = True,
    ) -> dict[str, Any]:
        scores: Counter[str] = Counter()
        for mapping in self.mappings:
            for technique_id in mapping.techniques:
                if not include_subtechniques:
                    technique_id = technique_id.split(".")[0]
                scores[technique_id] += 1

        techniques: list[dict[str, Any]] = []
        for technique_id in sorted(scores):
            for tactic in self.catalog.tactics_for(technique_id):
                techniques.append(
                    {
                        "techniqueID": technique_id,
                        "tactic": tactic,
                        "score": scores[technique_id],
                        "color": "",
                        "comment": "",
                        "enabled": True,
                        "metadata": [],
                        "links": [],
                        "showSubtechniques": False,
                    }
                )

        highest_score = max_score if max_score is not None else max(scores.values(), default=0)
        return {
            "name": name,
            "versions": {
                "attack": self.catalog.version,
                "navigator": "4.8.1",
                "layer": "4.4",
            },
            "domain": self.catalog.domain,
            "description": description
            or "Sigma ATT&CK coverage generated by sigma_attack",
            "gradient": {
                "colors": [min_color, max_color],
                "minValue": min_score,
                "maxValue": highest_score,
            },
            "techniques": techniques,
        }

    @staticmethod
    def _escape(value: str) -> str:
        return value.replace("|", "\\|").replace("\n", " ")


def build_coverage(
    mappings: Iterable[AttackMapping],
    catalog: AttackCatalog | None = None,
) -> CoverageReport:
    """Build a coverage report from ATT&CK mappings."""

    return CoverageReport(mappings, catalog=catalog)

