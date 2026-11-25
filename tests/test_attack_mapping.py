#!/usr/bin/env python3
"""Tests for automatic Sigma to MITRE ATT&CK mapping and coverage reports."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sigma_attack import (  # noqa: E402
    AttackCatalog,
    AttackMapping,
    attack_tags_for,
    build_coverage,
    get_catalog,
    map_rule,
    map_rules,
    parse_attack_tags,
)
from sigma_attack.catalog import normalize_tactic, normalize_technique  # noqa: E402


FIXTURE_PATH = ROOT / "tests" / "fixtures" / "attack_mapping_ground_truth.json"


class AttackMappingGroundTruthTests(unittest.TestCase):
    """Acceptance test: 50 reviewed rules must match the automatic mapping."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))

    def test_fixture_contains_50_unique_rules(self) -> None:
        rules = self.fixture["rules"]
        self.assertEqual(50, len(rules))
        paths = [rule["path"] for rule in rules]
        self.assertEqual(50, len(set(paths)))

    def test_50_rules_match_manual_annotations(self) -> None:
        mismatches = []
        for expected in self.fixture["rules"]:
            rule_path = ROOT / expected["path"]
            self.assertTrue(rule_path.is_file(), f"Missing rule: {expected['path']}")
            mapping = map_rule(rule_path)
            actual = {
                "title": mapping.title,
                "techniques": list(mapping.techniques),
                "tactics": list(mapping.tactics),
            }
            annotated = {
                "title": expected["title"],
                "techniques": expected["techniques"],
                "tactics": expected["tactics"],
            }
            if actual != annotated:
                mismatches.append(
                    {"path": expected["path"], "expected": annotated, "actual": actual}
                )
        self.assertEqual([], mismatches)

    def test_fixture_matches_bundled_catalog(self) -> None:
        self.assertEqual(get_catalog().version, self.fixture["attack_version"])


class AttackTagParsingTests(unittest.TestCase):
    def test_normalization_and_aliases(self) -> None:
        self.assertEqual("T1059.001", normalize_technique("attack.T1059.001"))
        self.assertEqual("T1059", normalize_technique("T1059"))
        self.assertIsNone(normalize_technique("T1059.1"))
        self.assertEqual("privilege-escalation", normalize_tactic("Privilege_Escalation"))
        self.assertEqual("command-and-control", normalize_tactic("command_and_control"))
        self.assertEqual("stealth", normalize_tactic("defense-evasion"))

    def test_parses_standard_and_legacy_tags(self) -> None:
        parsed = parse_attack_tags(
            [
                "attack.T1059.001",
                "attack.execution",
                "attack.defense-evasion",
                "attack.s0002",
                "attack.g0069",
                "attack.ds0005",
                "attack.m1040",
                "attack.c0001",
                "attack.not-a-real-tactic",
                "car.2016-04-005",
            ]
        )
        self.assertEqual({"T1059.001"}, parsed.techniques)
        self.assertEqual({"execution", "stealth"}, parsed.explicit_tactics)
        self.assertEqual({"S0002"}, parsed.software)
        self.assertEqual({"G0069"}, parsed.groups)
        self.assertEqual({"DS0005"}, parsed.data_sources)
        self.assertEqual({"M1040"}, parsed.mitigations)
        self.assertEqual({"C0001"}, parsed.campaigns)
        self.assertEqual({"not-a-real-tactic"}, parsed.unknown_attack_tags)
        self.assertEqual(set(), parsed.unknown_techniques)

    def test_unknown_technique_is_preserved_and_flagged(self) -> None:
        mapping = map_rule(
            {
                "id": "11111111-1111-1111-1111-111111111111",
                "title": "Unknown technique test",
                "tags": ["attack.t9999"],
            }
        )
        self.assertEqual(("T9999",), mapping.techniques)
        self.assertEqual(("T9999",), mapping.unknown_techniques)
        self.assertTrue(mapping.is_mapped)
        self.assertEqual((), mapping.tactics)

    def test_missing_tags_are_unmapped(self) -> None:
        mapping = map_rule({"id": "test", "title": "No ATT&CK tags", "tags": ["cve.2024.1234"]})
        self.assertFalse(mapping.is_mapped)
        self.assertEqual((), mapping.techniques)
        self.assertEqual((), mapping.tactics)

    def test_pysigma_tag_objects_are_supported(self) -> None:
        class Tag:
            def __init__(self, namespace: str, name: str) -> None:
                self.namespace = namespace
                self.name = name

            def __str__(self) -> str:
                return f"{self.namespace}.{self.name}"

        mapping = map_rule(
            {
                "id": "test",
                "title": "pySigma-style tag objects",
                "tags": [Tag("attack", "t1059.001"), Tag("attack", "execution")],
            }
        )
        self.assertEqual(("T1059.001",), mapping.techniques)
        self.assertEqual(("execution",), mapping.tactics)

    def test_attack_tags_for_round_trip(self) -> None:
        original = map_rule(
            {
                "id": "test",
                "title": "Round trip",
                "tags": ["attack.t1059.001", "attack.execution"],
            }
        )
        remapped = map_rule(
            {"id": "test", "title": "Round trip", "tags": list(attack_tags_for(original))}
        )
        self.assertEqual(original.techniques, remapped.techniques)
        self.assertEqual(original.tactics, remapped.tactics)


class CoverageReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mappings = (
            AttackMapping(
                rule_id="1",
                title="PowerShell one",
                path="one.yml",
                techniques=("T1059.001",),
                tactics=("execution",),
            ),
            AttackMapping(
                rule_id="2",
                title="PowerShell two",
                path="two.yml",
                techniques=("T1059.001",),
                explicit_tactics=("persistence",),
                tactics=("execution", "persistence"),
            ),
            AttackMapping(
                rule_id="3",
                title="LSASS access",
                path="three.yml",
                techniques=("T1003.001",),
                tactics=("credential-access",),
            ),
            AttackMapping(rule_id="4", title="Unmapped", path="four.yml"),
        )
        cls.report = build_coverage(cls.mappings)

    def test_summary_and_aggregation(self) -> None:
        summary = self.report.summary()
        self.assertEqual(4, summary["rules_total"])
        self.assertEqual(3, summary["rules_with_attack_technique"])
        self.assertEqual(1, summary["rules_without_technique"])
        self.assertEqual(1, summary["rules_without_any_attack_mapping"])
        self.assertEqual(75.0, summary["rule_coverage_percent"])
        self.assertEqual(2, self.report.by_technique["T1059.001"].rule_count)
        self.assertEqual(("execution",), self.report.by_technique["T1059.001"].tactics)

    def test_tactic_coverage_has_catalog_denominator(self) -> None:
        execution = self.report.by_tactic["execution"]
        self.assertGreater(len(execution.catalog_techniques), 0)
        self.assertIn("T1059.001", execution.covered_techniques)
        self.assertGreater(len(execution.uncovered_techniques), 0)
        self.assertGreater(execution.coverage_percent, 0)

    def test_json_report_is_serializable_and_contains_rule_refs(self) -> None:
        data = self.report.to_dict()
        encoded = json.dumps(data, sort_keys=True)
        decoded = json.loads(encoded)
        self.assertEqual("20.1", decoded["attack_version"])
        self.assertEqual(
            ["one.yml", "two.yml"],
            [rule["path"] for rule in decoded["by_technique"]["T1059.001"]["rules"]],
        )
        self.assertEqual(["four.yml"], [rule["path"] for rule in decoded["rules_without_technique"]])

    def test_markdown_report(self) -> None:
        markdown = self.report.to_markdown(max_unmapped=1, top_techniques=2)
        self.assertIn("# MITRE ATT&CK Coverage Report", markdown)
        self.assertIn("Rules scanned: 4", markdown)
        self.assertIn("T1059.001", markdown)
        self.assertIn("four.yml", markdown)
        self.assertIn("Uncovered techniques by tactic", markdown)

    def test_navigator_layer_is_converter_compatible(self) -> None:
        layer = self.report.to_navigator_layer(max_score=10)
        self.assertEqual("enterprise-attack", layer["domain"])
        self.assertEqual({"attack", "navigator", "layer"}, set(layer["versions"]))
        self.assertEqual(10, layer["gradient"]["maxValue"])
        powershell = [
            technique
            for technique in layer["techniques"]
            if technique["techniqueID"] == "T1059.001"
        ]
        self.assertEqual(1, len(powershell))
        self.assertEqual("execution", powershell[0]["tactic"])
        self.assertEqual(2, powershell[0]["score"])
        self.assertEqual(
            {
                "techniqueID",
                "tactic",
                "score",
                "color",
                "comment",
                "enabled",
                "metadata",
                "links",
                "showSubtechniques",
            },
            set(powershell[0]),
        )

    def test_unknown_entities_are_reported(self) -> None:
        report = build_coverage(
            (
                AttackMapping(
                    rule_id="x",
                    title="Unknown",
                    path="unknown.yml",
                    techniques=("T9999",),
                    unknown_techniques=("T9999",),
                    unknown_attack_tags=("not-a-real-tactic",),
                ),
            )
        )
        self.assertEqual(("T9999",), report.unknown_techniques)
        self.assertIn("not-a-real-tactic", report.unknown_attack_tags)
        self.assertEqual(1, report.summary()["techniques_unknown"])


class CatalogTests(unittest.TestCase):
    def test_catalog_has_known_reference_entries(self) -> None:
        catalog = get_catalog()
        self.assertEqual(("execution",), catalog.tactics_for("T1059.001"))
        self.assertEqual(
            ("credential-access",), catalog.tactics_for("T1003.001")
        )
        self.assertEqual(
            ("stealth", "persistence", "execution"), catalog.tactics_for("T1197")
        )
        self.assertTrue(catalog.is_known_tactic("defense-evasion"))
        self.assertFalse(catalog.is_known_technique("T9999"))

    def test_catalog_can_be_built_from_stix(self) -> None:
        stix = {
            "objects": [
                {"type": "x-mitre-collection", "x_mitre_version": "99.0"},
                {
                    "type": "x-mitre-tactic",
                    "x_mitre_shortname": "execution",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "TA0002"}
                    ],
                },
                {
                    "type": "attack-pattern",
                    "name": "Test Technique",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T9998"}
                    ],
                    "kill_chain_phases": [
                        {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                    ],
                },
            ]
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            stix_path = Path(temp_dir) / "enterprise-attack.json"
            stix_path.write_text(json.dumps(stix), encoding="utf-8")
            catalog = AttackCatalog.from_stix(stix_path)
        self.assertEqual("99.0", catalog.version)
        self.assertEqual(("execution",), catalog.tactics_for("T9998"))


class RepositoryRuleTests(unittest.TestCase):
    def test_all_generic_rule_attack_tags_are_known(self) -> None:
        mappings = map_rules(ROOT / "rules")
        report = build_coverage(mappings)
        self.assertGreater(len(mappings), 3000)
        self.assertEqual((), report.unknown_techniques)
        self.assertEqual({}, report.unknown_attack_tags)


class ConverterCompatibilityTests(unittest.TestCase):
    def test_pysigma_rule_object_matches_yaml_mapping(self) -> None:
        try:
            from sigma.rule import SigmaRule
        except ImportError:
            self.skipTest("pySigma is not installed")

        rule_path = (
            ROOT
            / "rules/windows/process_creation/proc_creation_win_powershell_download_patterns.yml"
        )
        plain = map_rule(rule_path)
        py_sigma_rule = SigmaRule.from_yaml(rule_path.read_text(encoding="utf-8"))
        from_object = map_rule(py_sigma_rule)
        self.assertEqual(plain.techniques, from_object.techniques)
        self.assertEqual(plain.tactics, from_object.tactics)
        self.assertEqual(plain.rule_id, from_object.rule_id)
        # Mapping must not mutate the rule used by converters.
        self.assertEqual(
            ["attack.execution", "attack.t1059.001"],
            py_sigma_rule.to_dict()["tags"],
        )

    def test_pysigma_attack_scores_match_mapping_counts(self) -> None:
        try:
            from sigma.analyze.attack import calculate_attack_scores, score_count
            from sigma.collection import SigmaCollection
        except ImportError:
            self.skipTest("pySigma is not installed")

        rule_paths = [
            ROOT
            / "rules/windows/process_creation/proc_creation_win_powershell_download_patterns.yml",
            ROOT
            / "rules/windows/process_creation/proc_creation_win_7zip_exfil_dmp_files.yml",
            ROOT
            / "rules/windows/process_creation/proc_creation_win_hktl_mimikatz_command_line.yml",
        ]
        collection = SigmaCollection.from_yaml(
            "\n---\n".join(
                rule_path.read_text(encoding="utf-8") for rule_path in rule_paths
            )
        )
        py_scores = calculate_attack_scores(collection, score_count)
        py_counts = Counter(
            {
                technique.upper(): score
                for technique, score in py_scores.items()
                if normalize_technique(technique) is not None
            }
        )
        our_counts = Counter(
            technique
            for mapping in map_rules(rule_paths)
            for technique in mapping.techniques
        )
        self.assertEqual(py_counts, our_counts)


class CliTests(unittest.TestCase):
    RULE = (
        ROOT
        / "rules/windows/process_creation/proc_creation_win_powershell_download_patterns.yml"
    )

    @classmethod
    def run_cli(cls, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "sigma_attack", *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_map_command(self) -> None:
        result = self.run_cli("map", str(self.RULE))
        self.assertEqual(0, result.returncode, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(["T1059.001"], data[0]["techniques"])
        self.assertEqual(["execution"], data[0]["tactics"])

    def test_coverage_command_markdown(self) -> None:
        result = self.run_cli(
            "coverage", str(self.RULE), "--format", "markdown", "--top-techniques", "1"
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("# MITRE ATT&CK Coverage Report", result.stdout)
        self.assertIn("T1059.001", result.stdout)

    def test_navigator_command_writes_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "layer.json"
            result = self.run_cli("navigator", str(self.RULE), "-o", str(output))
            self.assertEqual(0, result.returncode, result.stderr)
            layer = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual("enterprise-attack", layer["domain"])
        self.assertEqual("T1059.001", layer["techniques"][0]["techniqueID"])

    def test_validate_command_reports_unknown_tags(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            rule_path = Path(temp_dir) / "unknown.yml"
            rule_path.write_text(
                yaml.safe_dump(
                    {
                        "title": "Unknown tags",
                        "id": "22222222-2222-2222-2222-222222222222",
                        "status": "test",
                        "description": "test",
                        "logsource": {"category": "process_creation", "product": "windows"},
                        "detection": {"selection": {"Image": "test.exe"}, "condition": "selection"},
                        "tags": ["attack.t9999", "attack.not-a-real-tactic"],
                    }
                ),
                encoding="utf-8",
            )
            result = self.run_cli("validate", str(rule_path))
        self.assertEqual(1, result.returncode)
        self.assertIn("T9999", result.stderr)
        self.assertIn("not-a-real-tactic", result.stderr)

    def test_coverage_fail_under(self) -> None:
        result = self.run_cli(
            "coverage", str(self.RULE), "--format", "json", "--fail-under", "101"
        )
        self.assertEqual(1, result.returncode)
        self.assertIn("below required", result.stderr)


if __name__ == "__main__":
    unittest.main()
