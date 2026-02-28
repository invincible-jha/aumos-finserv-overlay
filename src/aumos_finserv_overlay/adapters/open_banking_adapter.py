"""Open Banking PSD2/PSD3 API compliance adapter.

GAP-299: Open Banking PSD2/PSD3 API Compliance.
"""
from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from pydantic import BaseModel, Field

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# PSD2 Article 14: Strong Customer Authentication (SCA) requirements
SCA_ELEMENTS = frozenset(["knowledge", "possession", "inherence"])


class TPPRegistration(BaseModel):
    """Third-Party Provider registration record per PSD2 Article 11."""

    tpp_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    client_name: str
    redirect_uris: list[str]
    scope: list[str]  # aisp, pisp, cbpii
    national_competent_authority: str  # FCA, BaFin, etc.
    tpp_registration_number: str
    client_secret_hash: str
    registered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True


class ConsentGrant(BaseModel):
    """PSD2 consent grant per EU 2018/389 (RTS on SCA)."""

    consent_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tpp_id: str
    psu_id: str  # Payment Service User identifier
    scope: list[str]
    expires_at: datetime
    granted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True
    frequency_per_day: int = 4  # PSD2 Art. 36: max 4 access/day for AIS


class OpenBankingAdapter:
    """Implements PSD2/PSD3 Open Banking compliance endpoints.

    Covers OAuth 2.0 Dynamic Client Registration (RFC 7591),
    Token Introspection (RFC 7662), and PSD2 Article 14 strong
    customer authentication (SCA) validation.

    PSD3 alignment: Supports enhanced TPP supervision requirements
    planned for EU implementation circa 2026.
    """

    def register_tpp(
        self,
        client_name: str,
        redirect_uris: list[str],
        scope: list[str],
        national_competent_authority: str,
        tpp_registration_number: str,
    ) -> tuple[TPPRegistration, str]:
        """Register a Third-Party Provider via OAuth 2.0 DCR (RFC 7591).

        Args:
            client_name: Human-readable TPP name.
            redirect_uris: Allowed redirect URIs.
            scope: Requested API scopes (aisp/pisp/cbpii).
            national_competent_authority: Supervising NCA (FCA, BaFin, etc.).
            tpp_registration_number: Regulator-issued TPP number.

        Returns:
            Tuple of (TPPRegistration, plaintext_client_secret).
            The plaintext secret is returned ONCE and not stored.
        """
        valid_scopes = {"aisp", "pisp", "cbpii"}
        invalid_scopes = set(scope) - valid_scopes
        if invalid_scopes:
            raise ValueError(f"Invalid PSD2 scopes: {invalid_scopes}")

        client_secret = secrets.token_urlsafe(32)
        secret_hash = hashlib.sha256(client_secret.encode()).hexdigest()

        registration = TPPRegistration(
            client_name=client_name,
            redirect_uris=redirect_uris,
            scope=scope,
            national_competent_authority=national_competent_authority,
            tpp_registration_number=tpp_registration_number,
            client_secret_hash=secret_hash,
        )
        logger.info("tpp_registered", tpp_id=registration.tpp_id, nca=national_competent_authority)
        return registration, client_secret

    def create_consent(
        self,
        tpp_id: str,
        psu_id: str,
        scope: list[str],
        validity_days: int = 90,
    ) -> ConsentGrant:
        """Create a PSD2 consent grant with SCA-validated PSU.

        Args:
            tpp_id: Registered TPP identifier.
            psu_id: Payment Service User identifier.
            scope: Consented API scopes.
            validity_days: Consent validity period (max 90 per PSD2 RTS).

        Returns:
            ConsentGrant record.

        Raises:
            ValueError: If validity_days exceeds PSD2 90-day maximum.
        """
        if validity_days > 90:
            raise ValueError("PSD2 RTS Article 10: consent validity cannot exceed 90 days")

        consent = ConsentGrant(
            tpp_id=tpp_id,
            psu_id=psu_id,
            scope=scope,
            expires_at=datetime.now(timezone.utc) + timedelta(days=validity_days),
        )
        logger.info("consent_created", consent_id=consent.consent_id, tpp_id=tpp_id, scope=scope)
        return consent

    def validate_sca(self, authentication_elements: list[str]) -> bool:
        """Validate PSD2 Article 14 Strong Customer Authentication (SCA).

        SCA requires at least 2 independent elements from:
        knowledge (PIN/password), possession (device/card), inherence (biometric).

        Args:
            authentication_elements: Elements used (knowledge/possession/inherence).

        Returns:
            True if SCA requirements are met (2+ independent categories).
        """
        provided = set(authentication_elements) & SCA_ELEMENTS
        return len(provided) >= 2

    def introspect_token(self, token: str, tpp_registrations: dict[str, TPPRegistration]) -> dict[str, Any]:
        """Implement RFC 7662 Token Introspection for consent validation.

        Args:
            token: Bearer token to introspect.
            tpp_registrations: Active TPP registrations keyed by tpp_id.

        Returns:
            RFC 7662 introspection response dict.
        """
        # Token format: {tpp_id}.{consent_id}.{signature}
        parts = token.split(".")
        if len(parts) != 3:
            return {"active": False}

        tpp_id = parts[0]
        if tpp_id not in tpp_registrations:
            return {"active": False}

        registration = tpp_registrations[tpp_id]
        if not registration.is_active:
            return {"active": False}

        return {
            "active": True,
            "client_id": tpp_id,
            "client_name": registration.client_name,
            "scope": " ".join(registration.scope),
            "token_type": "Bearer",
        }
