"""Evidence provenance classifications for integration observations."""

from __future__ import annotations

# Application-facing evidence classes (EOS-04).
SYNTHETIC = "SYNTHETIC"
LIVE_READ_ONLY = "LIVE_READ_ONLY"
CACHED = "CACHED"
UNVERIFIED = "UNVERIFIED"
ERROR = "ERROR"
UNAVAILABLE = "UNAVAILABLE"

# Legacy synthetic adapter label (preserved).
SIMULATED_INTEGRATION = "simulated_integration"
EXTERNALLY_VERIFIED = "externally_verified"

EVIDENCE_CLASSES = frozenset(
    {
        SYNTHETIC,
        LIVE_READ_ONLY,
        CACHED,
        UNVERIFIED,
        ERROR,
        UNAVAILABLE,
        SIMULATED_INTEGRATION,
        EXTERNALLY_VERIFIED,
    }
)


def is_synthetic(evidence_class: str) -> bool:
    return evidence_class in {SYNTHETIC, SIMULATED_INTEGRATION}


def is_live_or_cached(evidence_class: str) -> bool:
    return evidence_class in {LIVE_READ_ONLY, CACHED, EXTERNALLY_VERIFIED}
