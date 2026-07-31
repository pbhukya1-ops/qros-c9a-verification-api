"""QROS C9A read-only verification API."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException

from verification import (
    attestation_summary,
    parent_baseline_summary,
    verify_c8a_bundle,
)


app = FastAPI(
    title="QROS C9A Verification API",
    version="0.2.0",
    description=(
        "Read-only cryptographic verification API for "
        "the immutable QROS C8A parent baseline."
    ),
)


@app.get("/health")
def health() -> dict[str, object]:
    verification = verify_c8a_bundle()

    return {
        "status": (
            "healthy"
            if verification["accepted"]
            else "degraded"
        ),
        "candidate": "QROS_C9A_VERIFICATION_API",
        "parent": (
            "QROS_TRACK_B_FINAL_CANDIDATE_C8A"
        ),
        "parent_verified": verification["accepted"],
        "promotion_boundary": (
            "SHADOW_ONLY_NO_TRADE"
        ),
        "read_only": True,
        "broker_api_calls_allowed": False,
        "live_orders_allowed": False,
        "v11_process_control_allowed": False,
        "observation_can_authorize_trade": False,
        "default_decision": "NO_TRADE",
    }


@app.get("/verification/c8a")
def verify_c8a() -> dict[str, object]:
    report = verify_c8a_bundle()

    if not report["accepted"]:
        raise HTTPException(
            status_code=503,
            detail=report,
        )

    return report


@app.get("/verification/c8a/attestation")
def verify_c8a_attestation() -> dict[str, object]:
    report = attestation_summary()

    if not report["accepted"]:
        raise HTTPException(
            status_code=503,
            detail=report,
        )

    return report


@app.get("/verification/c8a/parent-baseline")
def verify_parent_baseline() -> dict[str, object]:
    report = parent_baseline_summary()

    if not report["accepted"]:
        raise HTTPException(
            status_code=503,
            detail=report,
        )

    return report
