# QROS C9A Verification API

Read-only FastAPI verification service for the immutable QROS C8A
parent baseline.

## Safety boundary

- No broker API calls
- No order placement
- No V11 process control
- No observation-based trade authorization
- Default decision: `NO_TRADE`
- Promotion boundary: `SHADOW_ONLY_NO_TRADE`
