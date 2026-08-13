#!/usr/bin/env python3
"""Validate the advisory Phase-E scanner relationship catalog."""
from __future__ import annotations

import argparse
import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
CLASSES = {"EXACT", "RELATED", "OVERLAPPING", "NOT_COMPARABLE", "UNKNOWN"}
SHA40 = re.compile(r"[0-9a-f]{40}")
REQUIRED_RELATIONSHIP = {
    "relationship_id", "classification", "checkov_rule_id", "kics_query_id",
    "trivy_check_id", "semantics", "authoritative_sources", "fixtures",
    "variable_default_behavior", "resource_type_scope",
    "known_semantic_differences", "exact_blockers",
    "independent_reviewer_signoff",
}


class UniqueLoader(yaml.SafeLoader):
    pass


def _unique_mapping(loader: UniqueLoader, node: yaml.MappingNode, deep: bool = False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError(f"duplicate catalog key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping,
)


def validate_catalog(path: Path) -> dict:
    data = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueLoader)
    if type(data) is not dict:
        raise ValueError("catalog root must be a mapping")
    if data.get("contract") != "iac-guard-v-control-relationship-catalog-v1":
        raise ValueError("catalog contract is unsupported")
    if data.get("catalog_status") != "ADVISORY_ONLY":
        raise ValueError("scanner relationship catalog must remain advisory")
    locks = data.get("scanner_locks")
    if type(locks) is not dict or set(locks) != {"checkov", "kics", "trivy"}:
        raise ValueError("catalog requires exactly three scanner locks")
    for scanner, lock in locks.items():
        if type(lock) is not dict or not SHA40.fullmatch(str(lock.get("source_commit", ""))):
            raise ValueError(f"{scanner} source commit is not immutable")
        if not all(type(lock.get(key)) is str and lock[key] for key in (
            "version", "source_repository", "policy_identity",
        )):
            raise ValueError(f"{scanner} lock is incomplete")
    relationships = data.get("relationships")
    if type(relationships) is not list:
        raise ValueError("relationships must be a list")
    ids: set[str] = set()
    exact_count = 0
    scanner_ids = {name: set() for name in ("checkov", "kics", "trivy")}
    for item in relationships:
        if type(item) is not dict or set(item) != REQUIRED_RELATIONSHIP:
            raise ValueError("relationship fields do not match catalog-v1")
        relationship_id = item["relationship_id"]
        if type(relationship_id) is not str or not relationship_id or relationship_id in ids:
            raise ValueError("relationship ids must be nonempty and unique")
        ids.add(relationship_id)
        if item["classification"] not in CLASSES:
            raise ValueError("relationship classification is not closed")
        for scanner, field in (
            ("checkov", "checkov_rule_id"), ("kics", "kics_query_id"),
            ("trivy", "trivy_check_id"),
        ):
            native_id = item[field]
            if type(native_id) is not str or not native_id or native_id in scanner_ids[scanner]:
                raise ValueError(f"{scanner} relationship id is missing or duplicated")
            scanner_ids[scanner].add(native_id)
        if set(item["semantics"]) != {"checkov", "kics", "trivy"}:
            raise ValueError("every scanner requires documented semantics")
        if set(item["authoritative_sources"]) != {"checkov", "kics", "trivy"}:
            raise ValueError("every scanner requires an authoritative source")
        if set(item["fixtures"]) != {"positive", "negative", "boundary"}:
            raise ValueError("relationship requires positive, negative, and boundary fixtures")
        for fixture in item["fixtures"].values():
            candidate = (ROOT / fixture).resolve()
            try:
                candidate.relative_to(ROOT)
            except ValueError as exc:
                raise ValueError("fixture escapes repository") from exc
            if not candidate.is_file() or candidate.is_symlink():
                raise ValueError(f"fixture is unavailable or unsafe: {fixture}")
        if not item["resource_type_scope"]:
            raise ValueError("resource type scope cannot be empty")
        if item["classification"] == "EXACT":
            exact_count += 1
            if item["exact_blockers"]:
                raise ValueError("EXACT mapping cannot retain semantic blockers")
            signoff = item["independent_reviewer_signoff"]
            if type(signoff) is not dict or set(signoff) != {
                "reviewer", "reviewed_at_utc", "evidence_sha256", "signature",
            } or not all(signoff.values()):
                raise ValueError("EXACT mapping requires complete independent sign-off")
        elif not item["exact_blockers"]:
            raise ValueError("non-EXACT relationship must explain exact blockers")
    if exact_count > 5 or data.get("exact_mapping_count") != exact_count:
        raise ValueError("EXACT mapping count is invalid")
    return data


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("catalog", nargs="?", type=Path, default=ROOT / "controls/catalog-v1.yml")
    args = parser.parse_args()
    data = validate_catalog(args.catalog)
    print(f"CONTROL_CATALOG: PASS ({len(data['relationships'])} relationships, "
          f"{data['exact_mapping_count']} EXACT)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
