from __future__ import annotations

from datetime import datetime, timezone

from .models import EvidenceClaim


def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def claim_is_stale(claim: EvidenceClaim, generated_at: str) -> bool:
    freshness = claim.raw.get("freshness", {})
    expires_at = freshness.get("expiresAt")
    if not expires_at:
        return False
    return parse_timestamp(expires_at) < parse_timestamp(generated_at)
