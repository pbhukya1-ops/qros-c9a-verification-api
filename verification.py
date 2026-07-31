"""Read-only verification of the immutable QROS C8A baseline."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Mapping


EVIDENCE_ROOT = (
    Path(__file__).resolve().parent / "evidence_root"
)

EXPECTED_RELEASE_ID = (
    "5098bde8654f6c83532cced2d11e76dd"
    "1da5707123d0ba1aebb005dc2ac3bfff"
)

EXPECTED_ATTESTATION_SHA256 = (
    "d539080fd027f9ed07e2d91f6ca773c7"
    "389b3b7531af868054b9acda99adbf03"
)

EXPECTED_BOUNDARY = "SHADOW_ONLY_NO_TRADE"

FINAL_DIR = (
    "reports/track_b_candidate_evidence/"
    "FINAL_CANDIDATE_C8A"
)

PARENT_DIR = (
    "reports/track_b_candidate_evidence/"
    "PARENT_BASELINE_C9A"
)

ATTESTATION_PATH = (
    f"{FINAL_DIR}/"
    "track_b_final_candidate_attestation.json"
)

ATTESTATION_MANIFEST_PATH = (
    f"{FINAL_DIR}/"
    "track_b_final_candidate_attestation.sha256"
)

METADATA_PATH = (
    f"{FINAL_DIR}/c8a_acceptance_metadata.json"
)

ACCEPTED_SOURCES_PATH = (
    f"{FINAL_DIR}/c8a_accepted_sources.sha256"
)

ACCEPTANCE_SEAL_PATH = (
    f"{FINAL_DIR}/c8a_acceptance_seal.sha256"
)

PARENT_ANCHOR_PATH = (
    f"{PARENT_DIR}/c8a_parent_baseline_anchor.json"
)

PARENT_CHAIN_PATH = (
    f"{PARENT_DIR}/c8a_parent_baseline_chain.sha256"
)

PARENT_SEAL_PATH = (
    f"{PARENT_DIR}/c8a_parent_baseline_seal.sha256"
)

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class VerificationError(ValueError):
    """Raised for malformed verification evidence."""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _safe_path(
    root: Path,
    relative: str,
) -> Path:
    supplied = Path(relative)

    if supplied.is_absolute() or ".." in supplied.parts:
        raise VerificationError(
            "unsafe evidence path: " + relative
        )

    resolved_root = root.resolve()
    resolved = (resolved_root / supplied).resolve()

    if not resolved.is_relative_to(resolved_root):
        raise VerificationError(
            "evidence path escaped root: " + relative
        )

    current = resolved_root

    for part in supplied.parts:
        current = current / part

        if current.is_symlink():
            raise VerificationError(
                "symlink evidence rejected: " + relative
            )

    return resolved


def _load_json(
    root: Path,
    relative: str,
) -> Mapping[str, object]:
    path = _safe_path(root, relative)

    if not path.is_file():
        raise VerificationError(
            "JSON evidence not found: " + relative
        )

    try:
        value = json.loads(
            path.read_text(encoding="utf-8")
        )
    except UnicodeDecodeError as exc:
        raise VerificationError(
            "JSON evidence is not UTF-8: " + relative
        ) from exc
    except json.JSONDecodeError as exc:
        raise VerificationError(
            "invalid JSON evidence: "
            f"{relative}:line={exc.lineno}:"
            f"column={exc.colno}"
        ) from exc

    if not isinstance(value, Mapping):
        raise VerificationError(
            "JSON evidence root is not an object: "
            + relative
        )

    return value


def verify_sha256_manifest(
    root: Path,
    manifest_relative: str,
) -> dict[str, object]:
    manifest_path = _safe_path(
        root,
        manifest_relative,
    )

    if not manifest_path.is_file():
        return {
            "accepted": False,
            "checked_count": 0,
            "reasons": [
                "MANIFEST_NOT_FOUND:"
                + manifest_relative
            ],
        }

    try:
        text = manifest_path.read_text(
            encoding="utf-8"
        )
    except UnicodeDecodeError:
        return {
            "accepted": False,
            "checked_count": 0,
            "reasons": [
                "MANIFEST_NOT_UTF8:"
                + manifest_relative
            ],
        }

    if not text.endswith("\n"):
        return {
            "accepted": False,
            "checked_count": 0,
            "reasons": [
                "MANIFEST_MISSING_FINAL_NEWLINE:"
                + manifest_relative
            ],
        }

    reasons: list[str] = []
    checked_count = 0
    seen_paths: set[str] = set()

    for line_number, line in enumerate(
        text.splitlines(),
        start=1,
    ):
        if not line:
            reasons.append(
                f"EMPTY_MANIFEST_LINE:{line_number}"
            )
            continue

        parts = line.split(maxsplit=1)

        if len(parts) != 2:
            reasons.append(
                f"INVALID_MANIFEST_LINE:{line_number}"
            )
            continue

        expected_hash, relative = parts
        relative = relative.strip()

        if not SHA256_PATTERN.fullmatch(
            expected_hash
        ):
            reasons.append(
                f"INVALID_SHA256:{line_number}"
            )
            continue

        if relative in seen_paths:
            reasons.append(
                "DUPLICATE_MANIFEST_PATH:"
                + relative
            )
            continue

        seen_paths.add(relative)

        try:
            target = _safe_path(root, relative)
        except VerificationError as exc:
            reasons.append(str(exc))
            continue

        if not target.is_file():
            reasons.append(
                "TARGET_NOT_FOUND:" + relative
            )
            continue

        actual_hash = _sha256(target)
        checked_count += 1

        if actual_hash != expected_hash:
            reasons.append(
                "HASH_MISMATCH:" + relative
            )

    if checked_count == 0:
        reasons.append("NO_TARGETS_VERIFIED")

    return {
        "accepted": not reasons,
        "checked_count": checked_count,
        "reasons": reasons,
    }


def verify_c8a_bundle(
    evidence_root: Path = EVIDENCE_ROOT,
) -> dict[str, object]:
    root = evidence_root.resolve()
    reasons: list[str] = []

    manifest_checks = {
        "parent_chain": verify_sha256_manifest(
            root,
            PARENT_CHAIN_PATH,
        ),
        "parent_seal": verify_sha256_manifest(
            root,
            PARENT_SEAL_PATH,
        ),
        "acceptance_seal": verify_sha256_manifest(
            root,
            ACCEPTANCE_SEAL_PATH,
        ),
        "attestation_manifest": (
            verify_sha256_manifest(
                root,
                ATTESTATION_MANIFEST_PATH,
            )
        ),
    }

    for name, report in manifest_checks.items():
        if not report["accepted"]:
            reasons.append(
                "MANIFEST_REJECTED:" + name
            )
            reasons.extend(
                f"{name}:{reason}"
                for reason in report["reasons"]
            )

    try:
        anchor = _load_json(
            root,
            PARENT_ANCHOR_PATH,
        )
        metadata = _load_json(
            root,
            METADATA_PATH,
        )
        attestation = _load_json(
            root,
            ATTESTATION_PATH,
        )
    except VerificationError as exc:
        return {
            "accepted": False,
            "status": "C8A_VERIFICATION_REJECTED",
            "release_id": None,
            "promotion_boundary": None,
            "read_only": True,
            "default_decision": "NO_TRADE",
            "broker_api_calls_allowed": False,
            "live_orders_allowed": False,
            "reasons": [str(exc)],
            "checks": manifest_checks,
        }

    attestation_file = _safe_path(
        root,
        ATTESTATION_PATH,
    )
    accepted_sources_file = _safe_path(
        root,
        ACCEPTED_SOURCES_PATH,
    )

    actual_attestation_sha256 = _sha256(
        attestation_file
    )
    actual_accepted_sources_sha256 = _sha256(
        accepted_sources_file
    )

    expected_values = (
        (
            "metadata.release_id",
            metadata.get("release_id"),
            EXPECTED_RELEASE_ID,
        ),
        (
            "metadata.status",
            metadata.get("status"),
            "ACCEPTED_AND_FROZEN",
        ),
        (
            "metadata.promotion_boundary",
            metadata.get("promotion_boundary"),
            EXPECTED_BOUNDARY,
        ),
        (
            "metadata.attestation_sha256",
            metadata.get("attestation_sha256"),
            EXPECTED_ATTESTATION_SHA256,
        ),
        (
            "attestation.release_id",
            attestation.get("release_id"),
            EXPECTED_RELEASE_ID,
        ),
        (
            "attestation.status",
            attestation.get("status"),
            EXPECTED_BOUNDARY,
        ),
        (
            "attestation.promotion_boundary",
            attestation.get(
                "promotion_boundary"
            ),
            EXPECTED_BOUNDARY,
        ),
        (
            "attestation.integration_decision",
            attestation.get(
                "integration_decision"
            ),
            "NO_TRADE",
        ),
        (
            "anchor.parent_release_id",
            anchor.get("parent_release_id"),
            EXPECTED_RELEASE_ID,
        ),
        (
            "anchor.parent_status",
            anchor.get("parent_status"),
            "ACCEPTED_AND_FROZEN",
        ),
        (
            "anchor.parent_promotion_boundary",
            anchor.get(
                "parent_promotion_boundary"
            ),
            EXPECTED_BOUNDARY,
        ),
        (
            "anchor.parent_attestation_sha256",
            anchor.get(
                "parent_attestation_sha256"
            ),
            EXPECTED_ATTESTATION_SHA256,
        ),
        (
            "actual_attestation_sha256",
            actual_attestation_sha256,
            EXPECTED_ATTESTATION_SHA256,
        ),
    )

    for name, actual, expected in expected_values:
        if actual != expected:
            reasons.append(
                "IDENTITY_MISMATCH:"
                f"{name}:expected={expected}:"
                f"actual={actual}"
            )

    safety_fields = (
        "broker_api_calls_allowed",
        "live_orders_allowed",
        "v11_process_control_allowed",
        "observation_can_authorize_trade",
        "control_authority",
        "future_data_allowed",
    )

    for source_name, payload in (
        ("metadata", metadata),
        ("attestation", attestation),
        ("anchor", anchor),
    ):
        for field in safety_fields:
            if (
                field in payload
                and payload.get(field) is not False
            ):
                reasons.append(
                    "UNSAFE_FIELD:"
                    f"{source_name}.{field}"
                )

    for source_name, payload in (
        ("metadata", metadata),
        ("attestation", attestation),
        ("anchor", anchor),
    ):
        if (
            payload.get("default_decision")
            != "NO_TRADE"
        ):
            reasons.append(
                "DEFAULT_DECISION_MISMATCH:"
                + source_name
            )

        if payload.get("fail_closed") is not True:
            reasons.append(
                "FAIL_CLOSED_MISMATCH:"
                + source_name
            )

    parent_evidence = anchor.get("parent_evidence")

    if not isinstance(parent_evidence, Mapping):
        reasons.append(
            "ANCHOR_PARENT_EVIDENCE_INVALID"
        )
    else:
        accepted_sources_entry = (
            parent_evidence.get(
                "accepted_sources_manifest"
            )
        )

        if not isinstance(
            accepted_sources_entry,
            Mapping,
        ):
            reasons.append(
                "ANCHOR_ACCEPTED_SOURCES_INVALID"
            )
        elif (
            accepted_sources_entry.get("sha256")
            != actual_accepted_sources_sha256
        ):
            reasons.append(
                "ACCEPTED_SOURCES_ANCHOR_MISMATCH"
            )

    accepted = not reasons

    return {
        "accepted": accepted,
        "status": (
            "C8A_PERMANENT_PARENT_BASELINE_VERIFIED"
            if accepted
            else "C8A_VERIFICATION_REJECTED"
        ),
        "release_id": EXPECTED_RELEASE_ID,
        "promotion_boundary": EXPECTED_BOUNDARY,
        "attestation_sha256": (
            actual_attestation_sha256
        ),
        "accepted_sources_manifest_sha256": (
            actual_accepted_sources_sha256
        ),
        "read_only": True,
        "control_authority": False,
        "broker_api_calls_allowed": False,
        "live_orders_allowed": False,
        "v11_process_control_allowed": False,
        "observation_can_authorize_trade": False,
        "default_decision": "NO_TRADE",
        "fail_closed": True,
        "checks": manifest_checks,
        "reasons": reasons,
    }


def attestation_summary(
    evidence_root: Path = EVIDENCE_ROOT,
) -> dict[str, object]:
    verification = verify_c8a_bundle(evidence_root)

    return {
        "accepted": verification["accepted"],
        "release_id": verification["release_id"],
        "attestation_sha256": (
            verification["attestation_sha256"]
        ),
        "promotion_boundary": (
            verification["promotion_boundary"]
        ),
        "default_decision": "NO_TRADE",
        "read_only": True,
    }


def parent_baseline_summary(
    evidence_root: Path = EVIDENCE_ROOT,
) -> dict[str, object]:
    verification = verify_c8a_bundle(evidence_root)

    return {
        "accepted": verification["accepted"],
        "status": verification["status"],
        "parent_candidate": (
            "QROS_TRACK_B_FINAL_CANDIDATE_C8A"
        ),
        "future_branch": "C9A_OR_LATER",
        "release_id": verification["release_id"],
        "promotion_boundary": (
            verification["promotion_boundary"]
        ),
        "parent_files_modifiable": False,
        "read_only": True,
        "default_decision": "NO_TRADE",
    }
