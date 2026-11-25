"""Command-line interface for Sigma ATT&CK mapping and coverage."""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from . import __version__
from .catalog import AttackCatalog, get_catalog
from .coverage import CoverageReport, build_coverage
from .mapping import map_rules


def _add_input_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "paths",
        nargs="+",
        metavar="PATH",
        help="Sigma rule file or directory. Directories are searched recursively.",
    )
    parser.add_argument(
        "-P",
        "--file-pattern",
        default="*.yml",
        help="Pattern used when searching directories.",
    )


def _add_output_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Write output to FILE instead of stdout.",
    )


def _write_output(text: str, output: str | None) -> None:
    if output:
        Path(output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
        if text and not text.endswith("\n"):
            sys.stdout.write("\n")


def _load_catalog(args: argparse.Namespace) -> AttackCatalog:
    return AttackCatalog.load(args.catalog) if args.catalog else get_catalog()


def _build_report(args: argparse.Namespace) -> CoverageReport:
    catalog = _load_catalog(args)
    mappings = map_rules(args.paths, file_pattern=args.file_pattern, catalog=catalog)
    return build_coverage(mappings, catalog=catalog)


def _cmd_map(args: argparse.Namespace) -> int:
    catalog = _load_catalog(args)
    mappings = map_rules(args.paths, file_pattern=args.file_pattern, catalog=catalog)
    if args.format == "json":
        text = json.dumps(
            [mapping.to_dict() for mapping in mappings],
            indent=2,
            ensure_ascii=False,
        )
    else:
        stream = io.StringIO()
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(
            [
                "path",
                "id",
                "title",
                "techniques",
                "tactics",
                "explicit_tactics",
                "unknown_techniques",
                "unknown_attack_tags",
            ]
        )
        for mapping in mappings:
            writer.writerow(
                [
                    mapping.path,
                    mapping.rule_id,
                    mapping.title,
                    ";".join(mapping.techniques),
                    ";".join(mapping.tactics),
                    ";".join(mapping.explicit_tactics),
                    ";".join(mapping.unknown_techniques),
                    ";".join(mapping.unknown_attack_tags),
                ]
            )
        text = stream.getvalue().rstrip("\n")
    _write_output(text, args.output)
    return 0


def _cmd_coverage(args: argparse.Namespace) -> int:
    report = _build_report(args)
    if args.format == "json":
        text = json.dumps(
            report.to_dict(include_rule_refs=not args.no_rule_refs),
            indent=2,
            ensure_ascii=False,
        )
    else:
        text = report.to_markdown(
            max_unmapped=args.max_unmapped,
            top_techniques=args.top_techniques,
            include_rule_refs=not args.no_rule_refs,
        )
    _write_output(text, args.output)

    if args.fail_under is not None:
        coverage = report.summary()["rule_coverage_percent"]
        if coverage < args.fail_under:
            print(
                f"ATT&CK rule coverage {coverage:.2f}% is below "
                f"required {args.fail_under:.2f}%",
                file=sys.stderr,
            )
            return 1
    return 0


def _cmd_navigator(args: argparse.Namespace) -> int:
    report = _build_report(args)
    layer = report.to_navigator_layer(
        name=args.name,
        min_score=args.min_score,
        max_score=args.max_score,
        min_color=args.min_color,
        max_color=args.max_color,
        include_subtechniques=not args.no_subtechniques,
    )
    _write_output(
        json.dumps(layer, indent=2, ensure_ascii=False),
        args.output,
    )
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    report = _build_report(args)
    errors: list[str] = []
    for technique_id in report.unknown_techniques:
        errors.append(f"Unknown ATT&CK technique: {technique_id}")
    for tag, mappings in report.unknown_attack_tags.items():
        errors.append(
            f"Unknown ATT&CK tag: attack.{tag} "
            f"({len(mappings)} rule{'s' if len(mappings) != 1 else ''})"
        )
    if args.fail_on_unmapped:
        for mapping in report.rules_without_technique:
            errors.append(f"Rule has no ATT&CK technique: {mapping.path or mapping.title}")

    summary = report.summary()
    print(
        "Validated "
        f"{summary['rules_total']} rules against ATT&CK {report.catalog.version}: "
        f"{summary['rules_with_attack_technique']} with techniques, "
        f"{summary['rules_without_technique']} without techniques."
    )
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m sigma_attack",
        description=(
            "Map Sigma rules to MITRE ATT&CK and generate coverage reports "
            "from standard attack.* tags."
        ),
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument(
        "--catalog",
        metavar="FILE",
        help="Use a custom ATT&CK catalog JSON instead of the bundled catalog.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    map_parser = subparsers.add_parser(
        "map", help="Print the ATT&CK mapping for each rule."
    )
    _add_input_arguments(map_parser)
    _add_output_argument(map_parser)
    map_parser.add_argument(
        "--format",
        choices=("json", "csv"),
        default="json",
        help="Output format (default: json).",
    )
    map_parser.set_defaults(func=_cmd_map)

    coverage_parser = subparsers.add_parser(
        "coverage", help="Generate a coverage report."
    )
    _add_input_arguments(coverage_parser)
    _add_output_argument(coverage_parser)
    coverage_parser.add_argument(
        "--format",
        choices=("json", "markdown"),
        default="markdown",
        help="Output format (default: markdown).",
    )
    coverage_parser.add_argument(
        "--max-unmapped",
        type=int,
        default=50,
        metavar="N",
        help="Maximum unmapped rules to list in markdown (default: 50).",
    )
    coverage_parser.add_argument(
        "--top-techniques",
        type=int,
        default=20,
        metavar="N",
        help="Number of covered techniques to list in markdown (default: 20).",
    )
    coverage_parser.add_argument(
        "--no-rule-refs",
        action="store_true",
        help="Omit per-rule references from JSON and markdown output.",
    )
    coverage_parser.add_argument(
        "--fail-under",
        type=float,
        metavar="PERCENT",
        help="Exit non-zero if technique rule coverage is below PERCENT.",
    )
    coverage_parser.set_defaults(func=_cmd_coverage)

    navigator_parser = subparsers.add_parser(
        "navigator", help="Generate an ATT&CK Navigator layer."
    )
    _add_input_arguments(navigator_parser)
    _add_output_argument(navigator_parser)
    navigator_parser.add_argument(
        "--name",
        default="Sigma ATT&CK Coverage",
        help="Navigator layer name.",
    )
    navigator_parser.add_argument("--min-score", type=int, default=0)
    navigator_parser.add_argument("--max-score", type=int, default=None)
    navigator_parser.add_argument("--min-color", default="#ffffff00")
    navigator_parser.add_argument("--max-color", default="#ff0000")
    navigator_parser.add_argument(
        "-S",
        "--no-subtechniques",
        action="store_true",
        help="Roll subtechnique scores up to their parent technique.",
    )
    navigator_parser.set_defaults(func=_cmd_navigator)

    validate_parser = subparsers.add_parser(
        "validate", help="Validate ATT&CK tags and optionally require mappings."
    )
    _add_input_arguments(validate_parser)
    validate_parser.add_argument(
        "--fail-on-unmapped",
        action="store_true",
        help="Fail if a rule has no ATT&CK technique.",
    )
    validate_parser.set_defaults(func=_cmd_validate)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

