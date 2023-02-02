from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .core.potential_secret import PotentialSecret

AWS_ACCESS_KEY_ID="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEYV"

class VerifiedResult(Enum):
    VERIFIED_FALSE = 1
    UNVERIFIED = 2
    VERIFIED_TRUE = 3

    @staticmethod
    def from_secret(secret: PotentialSecret) -> 'VerifiedResult':
        if secret.is_secret is None:
            return VerifiedResult.UNVERIFIED
        elif secret.is_secret:
            return VerifiedResult.VERIFIED_TRUE
        else:
            return VerifiedResult.VERIFIED_FALSE
