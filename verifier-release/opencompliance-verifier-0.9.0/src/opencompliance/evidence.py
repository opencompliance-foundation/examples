from __future__ import annotations

import json
from pathlib import Path

from .models import EvidenceClaim, FrameworkMapping


class EvidenceRegistry:
    def __init__(self, claims: list[EvidenceClaim]) -> None:
        self._claims = claims
        self._by_id = {claim.claim_id: claim for claim in claims}
        self._by_type: dict[str, list[EvidenceClaim]] = {}
        for claim in claims:
            self._by_type.setdefault(claim.claim_type, []).append(claim)

    @classmethod
    def from_path(cls, path: Path) -> "EvidenceRegistry":
        raw_claims = json.loads(path.read_text())
        claims = []
        for raw in raw_claims:
            mappings = [
                FrameworkMapping(
                    framework=item["framework"],
                    family=item["family"],
                    control_id=item.get("controlId"),
                )
                for item in raw["controlMappings"]
            ]
            claims.append(
                EvidenceClaim(
                    claim_id=raw["claimId"],
                    claim_type=raw["claimType"],
                    actor_type=raw["actor"]["actorType"],
                    payload=raw["payload"],
                    mappings=mappings,
                    raw=raw,
                )
            )
        return cls(claims)

    def all_claims(self) -> list[EvidenceClaim]:
        return list(self._claims)

    def by_type(self, claim_type: str) -> list[EvidenceClaim]:
        return list(self._by_type.get(claim_type, []))

    def get(self, claim_id: str) -> EvidenceClaim:
        return self._by_id[claim_id]

