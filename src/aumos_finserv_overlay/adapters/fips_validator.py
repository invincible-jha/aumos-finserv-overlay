"""FIPS 140-2 encryption compliance validator for aumos-finserv-overlay.

Validates cryptographic implementations against NIST FIPS 140-2 Level 1-3
requirements: approved algorithm verification, key length validation, mode
of operation checking, RNG compliance, self-test requirements, and
FIPS compliance certification.
"""

import uuid
from datetime import datetime, timezone
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# FIPS 140-2 approved symmetric algorithms (NIST FIPS 197, SP 800-67)
_APPROVED_SYMMETRIC: dict[str, dict[str, Any]] = {
    "AES-128-CBC": {"key_bits": 128, "approved": True, "fips_standard": "FIPS 197"},
    "AES-192-CBC": {"key_bits": 192, "approved": True, "fips_standard": "FIPS 197"},
    "AES-256-CBC": {"key_bits": 256, "approved": True, "fips_standard": "FIPS 197"},
    "AES-128-GCM": {"key_bits": 128, "approved": True, "fips_standard": "FIPS 197 + SP 800-38D"},
    "AES-192-GCM": {"key_bits": 192, "approved": True, "fips_standard": "FIPS 197 + SP 800-38D"},
    "AES-256-GCM": {"key_bits": 256, "approved": True, "fips_standard": "FIPS 197 + SP 800-38D"},
    "AES-128-CCM": {"key_bits": 128, "approved": True, "fips_standard": "FIPS 197 + SP 800-38C"},
    "AES-256-CCM": {"key_bits": 256, "approved": True, "fips_standard": "FIPS 197 + SP 800-38C"},
    "3DES-168": {"key_bits": 168, "approved": True, "fips_standard": "SP 800-67", "deprecated": True},
}

# FIPS 140-2 approved asymmetric algorithms (NIST SP 800-131A)
_APPROVED_ASYMMETRIC: dict[str, dict[str, Any]] = {
    "RSA-2048": {"key_bits": 2048, "approved": True, "fips_standard": "SP 800-131A Rev 2"},
    "RSA-3072": {"key_bits": 3072, "approved": True, "fips_standard": "SP 800-131A Rev 2"},
    "RSA-4096": {"key_bits": 4096, "approved": True, "fips_standard": "SP 800-131A Rev 2"},
    "ECDSA-P256": {"key_bits": 256, "approved": True, "fips_standard": "FIPS 186-5"},
    "ECDSA-P384": {"key_bits": 384, "approved": True, "fips_standard": "FIPS 186-5"},
    "ECDSA-P521": {"key_bits": 521, "approved": True, "fips_standard": "FIPS 186-5"},
    "ECDH-P256": {"key_bits": 256, "approved": True, "fips_standard": "SP 800-56A Rev 3"},
    "ECDH-P384": {"key_bits": 384, "approved": True, "fips_standard": "SP 800-56A Rev 3"},
    "EdDSA-Ed25519": {"key_bits": 256, "approved": False, "fips_standard": None, "note": "Not approved in FIPS 140-2"},
}

# FIPS 140-2 approved hash algorithms (NIST FIPS 180-4)
_APPROVED_HASH: dict[str, dict[str, Any]] = {
    "SHA-256": {"output_bits": 256, "approved": True, "fips_standard": "FIPS 180-4"},
    "SHA-384": {"output_bits": 384, "approved": True, "fips_standard": "FIPS 180-4"},
    "SHA-512": {"output_bits": 512, "approved": True, "fips_standard": "FIPS 180-4"},
    "SHA-3-256": {"output_bits": 256, "approved": True, "fips_standard": "FIPS 202"},
    "SHA-3-512": {"output_bits": 512, "approved": True, "fips_standard": "FIPS 202"},
    "HMAC-SHA-256": {"output_bits": 256, "approved": True, "fips_standard": "FIPS 198-1"},
    "HMAC-SHA-512": {"output_bits": 512, "approved": True, "fips_standard": "FIPS 198-1"},
    "MD5": {"output_bits": 128, "approved": False, "fips_standard": None, "note": "Not approved — use SHA-2"},
    "SHA-1": {"output_bits": 160, "approved": False, "fips_standard": None, "note": "Deprecated in FIPS 140-2 after 2014"},
}

# FIPS 140-2 approved DRBG (Deterministic Random Bit Generators)
_APPROVED_RNG: dict[str, dict[str, Any]] = {
    "CTR-DRBG-AES-256": {"approved": True, "fips_standard": "SP 800-90A Rev 1"},
    "HMAC-DRBG-SHA-256": {"approved": True, "fips_standard": "SP 800-90A Rev 1"},
    "HASH-DRBG-SHA-512": {"approved": True, "fips_standard": "SP 800-90A Rev 1"},
    "Dual-EC-DRBG": {"approved": False, "fips_standard": None, "note": "Withdrawn — backdoor discovered"},
    "ANSI-X9.31-PRNG": {"approved": False, "fips_standard": None, "note": "Deprecated in SP 800-131A Rev 2"},
}

# Non-approved algorithms that should trigger failures
_NON_APPROVED_ALGORITHMS = {
    "DES", "RC2", "RC4", "MD5", "SHA-1", "Blowfish", "CAST5",
    "ChaCha20", "Poly1305", "EdDSA-Ed25519", "Curve25519",
}

# FIPS 140-2 security level requirements
_FIPS_SECURITY_LEVELS: dict[int, dict[str, Any]] = {
    1: {
        "description": "Basic security requirements",
        "physical_security": "No specific physical security mechanisms",
        "authentication": "Role-based authentication",
        "typical_use": "Software-only cryptographic modules",
    },
    2: {
        "description": "Tamper-evident physical security",
        "physical_security": "Tamper-evident coatings/seals, pick-resistant locks",
        "authentication": "Role-based authentication",
        "typical_use": "Smartcards, HSMs for general use",
    },
    3: {
        "description": "Tamper-resistant physical security",
        "physical_security": "Tamper-responsive and tamper-resistant mechanisms",
        "authentication": "Identity-based authentication",
        "typical_use": "High-assurance HSMs, government systems",
    },
    4: {
        "description": "Highest physical security",
        "physical_security": "Complete physical envelope protection",
        "authentication": "Identity-based authentication with EFP/EFT",
        "typical_use": "Military, highly classified systems",
    },
}


class FIPSValidator:
    """Validates cryptographic implementations against FIPS 140-2 requirements.

    Verifies approved algorithm usage, key lengths, mode of operation,
    RNG compliance, module boundary definition, self-test requirements,
    and generates FIPS compliance certificates for cryptographic modules.
    """

    def __init__(self) -> None:
        """Initialize FIPS validator."""
        pass

    def verify_algorithms(
        self,
        algorithms_in_use: list[dict[str, Any]],
        module_name: str,
    ) -> dict[str, Any]:
        """Verify that all cryptographic algorithms are FIPS 140-2 approved.

        Checks each algorithm in use against the NIST Cryptographic Algorithm
        Validation Program (CAVP) approved lists for symmetric, asymmetric,
        hash, and MAC algorithms.

        Args:
            algorithms_in_use: List of algorithm config dicts with 'name',
                'type' ('symmetric'/'asymmetric'/'hash'/'rng'), 'purpose' keys.
            module_name: Name of the cryptographic module being assessed.

        Returns:
            Algorithm verification report dict with FIPS compliance status.
        """
        approved_algorithms: list[dict[str, Any]] = []
        non_approved_algorithms: list[dict[str, Any]] = []
        deprecated_algorithms: list[dict[str, Any]] = []

        for alg in algorithms_in_use:
            name = alg.get("name", "")
            alg_type = alg.get("type", "")
            purpose = alg.get("purpose", "")

            # Look up in approved lists
            alg_info: dict[str, Any] | None = None
            if alg_type == "symmetric":
                alg_info = _APPROVED_SYMMETRIC.get(name)
            elif alg_type == "asymmetric":
                alg_info = _APPROVED_ASYMMETRIC.get(name)
            elif alg_type == "hash":
                alg_info = _APPROVED_HASH.get(name)
            elif alg_type == "rng":
                alg_info = _APPROVED_RNG.get(name)

            if alg_info is None:
                # Unknown algorithm — check non-approved list
                is_explicitly_forbidden = name.upper() in {a.upper() for a in _NON_APPROVED_ALGORITHMS}
                non_approved_algorithms.append({
                    "name": name,
                    "type": alg_type,
                    "purpose": purpose,
                    "status": "NON_APPROVED",
                    "explicitly_forbidden": is_explicitly_forbidden,
                    "finding": f"Algorithm '{name}' is not in NIST CAVP approved list",
                    "remediation": "Replace with FIPS 140-2 approved equivalent",
                })
            elif not alg_info.get("approved", False):
                non_approved_algorithms.append({
                    "name": name,
                    "type": alg_type,
                    "purpose": purpose,
                    "status": "NON_APPROVED",
                    "fips_note": alg_info.get("note"),
                    "finding": f"Algorithm '{name}' is not FIPS 140-2 approved",
                    "remediation": "Replace with approved algorithm",
                })
            elif alg_info.get("deprecated", False):
                deprecated_algorithms.append({
                    "name": name,
                    "type": alg_type,
                    "purpose": purpose,
                    "status": "DEPRECATED",
                    "fips_standard": alg_info.get("fips_standard"),
                    "finding": f"Algorithm '{name}' is deprecated — plan migration",
                    "migration_deadline": "2030-12-31",
                })
            else:
                approved_algorithms.append({
                    "name": name,
                    "type": alg_type,
                    "purpose": purpose,
                    "status": "APPROVED",
                    "fips_standard": alg_info.get("fips_standard"),
                    "key_bits": alg_info.get("key_bits") or alg_info.get("output_bits"),
                })

        fips_compliant = len(non_approved_algorithms) == 0

        report = {
            "module_name": module_name,
            "total_algorithms_assessed": len(algorithms_in_use),
            "approved_count": len(approved_algorithms),
            "non_approved_count": len(non_approved_algorithms),
            "deprecated_count": len(deprecated_algorithms),
            "fips_compliant": fips_compliant,
            "approved_algorithms": approved_algorithms,
            "non_approved_algorithms": non_approved_algorithms,
            "deprecated_algorithms": deprecated_algorithms,
            "cavp_reference": "NIST Cryptographic Algorithm Validation Program (CAVP)",
            "fips_standard": "FIPS 140-2",
            "assessed_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "FIPS 140-2 algorithm verification complete",
            module_name=module_name,
            approved_count=len(approved_algorithms),
            non_approved_count=len(non_approved_algorithms),
            fips_compliant=fips_compliant,
        )

        return report

    def validate_key_lengths(
        self,
        key_configurations: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Validate cryptographic key lengths against FIPS 140-2 minimums.

        Checks key lengths against SP 800-131A Rev 2 minimums for all
        algorithm types, flagging configurations that fall below minimum
        security strength requirements.

        Args:
            key_configurations: List of key config dicts with 'algorithm',
                'key_length_bits', 'purpose', 'system' keys.

        Returns:
            Key length validation report dict with findings.
        """
        # Minimum key lengths per SP 800-131A Rev 2
        min_key_lengths: dict[str, int] = {
            "RSA": 2048,
            "ECDSA": 224,
            "ECDH": 224,
            "AES": 128,
            "3DES": 168,
            "HMAC-SHA": 112,  # Security strength (not full key length)
        }

        findings: list[dict[str, Any]] = []
        non_compliant: list[dict[str, Any]] = []
        compliant: list[dict[str, Any]] = []

        for config in key_configurations:
            algorithm = config.get("algorithm", "")
            key_length = config.get("key_length_bits", 0)
            system = config.get("system", "")
            purpose = config.get("purpose", "")

            # Find matching algorithm family
            matching_family = next(
                (fam for fam in min_key_lengths if algorithm.upper().startswith(fam.upper())),
                None,
            )

            if matching_family is None:
                findings.append({
                    "algorithm": algorithm,
                    "system": system,
                    "status": "UNKNOWN",
                    "finding": f"Cannot determine minimum key length for '{algorithm}'",
                })
                continue

            min_length = min_key_lengths[matching_family]
            key_compliant = key_length >= min_length

            finding = {
                "algorithm": algorithm,
                "system": system,
                "purpose": purpose,
                "key_length_bits": key_length,
                "minimum_required_bits": min_length,
                "compliant": key_compliant,
                "sp_800_131a_reference": "SP 800-131A Rev 2",
            }

            if key_compliant:
                compliant.append(finding)
            else:
                finding["finding"] = (
                    f"Key length {key_length} bits below SP 800-131A minimum {min_length} bits"
                )
                finding["remediation"] = f"Regenerate keys with minimum {min_length}-bit length"
                non_compliant.append(finding)

        report = {
            "total_configurations_assessed": len(key_configurations),
            "compliant_count": len(compliant),
            "non_compliant_count": len(non_compliant),
            "unknown_count": len(findings),
            "fips_compliant": len(non_compliant) == 0,
            "compliant_configurations": compliant,
            "non_compliant_configurations": non_compliant,
            "unknown_configurations": findings,
            "sp_800_131a_reference": "SP 800-131A Rev 2 — Transitioning the Use of Cryptographic Algorithms",
            "validated_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "FIPS 140-2 key length validation complete",
            total_assessed=len(key_configurations),
            non_compliant=len(non_compliant),
        )

        return report

    def check_rng_compliance(
        self,
        rng_implementations: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Check RNG/DRBG implementations for FIPS 140-2 compliance.

        Validates that random number generators use NIST-approved DRBGs
        per SP 800-90A Rev 1 and meet entropy source requirements.

        Args:
            rng_implementations: List of RNG config dicts with 'name',
                'entropy_source', 'seeding_mechanism', 'system' keys.

        Returns:
            RNG compliance check dict with approval status.
        """
        compliant_rngs: list[dict[str, Any]] = []
        non_compliant_rngs: list[dict[str, Any]] = []

        for rng in rng_implementations:
            name = rng.get("name", "")
            entropy_source = rng.get("entropy_source", "")
            system = rng.get("system", "")

            rng_info = _APPROVED_RNG.get(name)

            if rng_info is None:
                non_compliant_rngs.append({
                    "name": name,
                    "system": system,
                    "status": "NON_APPROVED",
                    "finding": f"DRBG '{name}' not in NIST SP 800-90A approved list",
                    "remediation": "Use CTR-DRBG-AES-256 or HMAC-DRBG-SHA-256",
                })
            elif not rng_info.get("approved", False):
                non_compliant_rngs.append({
                    "name": name,
                    "system": system,
                    "status": "NON_APPROVED",
                    "finding": rng_info.get("note", "Not approved"),
                    "remediation": "Replace with SP 800-90A Rev 1 approved DRBG",
                })
            else:
                entropy_adequate = entropy_source not in ("", "none", "static")
                compliant_rngs.append({
                    "name": name,
                    "system": system,
                    "status": "APPROVED",
                    "fips_standard": rng_info.get("fips_standard"),
                    "entropy_source": entropy_source,
                    "entropy_adequate": entropy_adequate,
                    "entropy_warning": None if entropy_adequate else "Entropy source appears insufficient",
                })

        result = {
            "total_rngs_assessed": len(rng_implementations),
            "compliant_count": len(compliant_rngs),
            "non_compliant_count": len(non_compliant_rngs),
            "fips_compliant": len(non_compliant_rngs) == 0,
            "compliant_rngs": compliant_rngs,
            "non_compliant_rngs": non_compliant_rngs,
            "sp_800_90a_reference": "SP 800-90A Rev 1 — Recommendation for DRBG",
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "FIPS 140-2 RNG compliance checked",
            total_assessed=len(rng_implementations),
            non_compliant=len(non_compliant_rngs),
        )

        return result

    def define_module_boundary(
        self,
        module_name: str,
        module_version: str,
        security_level: int,
        included_components: list[str],
        excluded_components: list[str],
        physical_boundary: str | None,
        software_boundary: str | None,
    ) -> dict[str, Any]:
        """Define the cryptographic module boundary for FIPS 140-2 assessment.

        Produces a module boundary definition document specifying what is
        included within the cryptographic boundary for validation purposes,
        per FIPS 140-2 Section 4.1.

        Args:
            module_name: Name of the cryptographic module.
            module_version: Module version string.
            security_level: Target FIPS 140-2 security level (1-4).
            included_components: Components inside the cryptographic boundary.
            excluded_components: Components explicitly outside the boundary.
            physical_boundary: Physical boundary description (for hardware modules).
            software_boundary: Software boundary description (for software modules).

        Returns:
            Module boundary definition dict.
        """
        if security_level not in _FIPS_SECURITY_LEVELS:
            security_level = 1

        level_info = _FIPS_SECURITY_LEVELS[security_level]

        boundary_definition = {
            "module_name": module_name,
            "module_version": module_version,
            "target_security_level": security_level,
            "security_level_description": level_info["description"],
            "physical_security_required": level_info["physical_security"],
            "authentication_required": level_info["authentication"],
            "typical_use_case": level_info["typical_use"],
            "cryptographic_boundary": {
                "included_components": included_components,
                "excluded_components": excluded_components,
                "physical_boundary": physical_boundary,
                "software_boundary": software_boundary,
            },
            "approved_services": [
                "Encryption and Decryption",
                "Digital Signature Generation and Verification",
                "Hash Computation",
                "Key Generation and Management",
                "Random Number Generation",
            ],
            "roles_and_services": {
                "crypto_officer": "Module initialization, key management, self-tests",
                "user": "Encryption, decryption, signing, verification",
            },
            "self_test_required": True,
            "key_zeroization_required": True,
            "cmvp_submission_required": security_level >= 2,
            "fips_standard": "FIPS 140-2 — Security Requirements for Cryptographic Modules",
            "defined_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "FIPS 140-2 module boundary defined",
            module_name=module_name,
            security_level=security_level,
        )

        return boundary_definition

    def generate_fips_certificate(
        self,
        tenant_id: uuid.UUID,
        module_name: str,
        module_version: str,
        security_level: int,
        algorithm_verification: dict[str, Any],
        key_validation: dict[str, Any],
        rng_check: dict[str, Any],
        self_tests_passed: bool,
    ) -> dict[str, Any]:
        """Generate a FIPS 140-2 compliance certificate for a cryptographic module.

        Produces a structured compliance certificate summarizing all validation
        activities, findings, and overall FIPS 140-2 compliance determination.

        Args:
            tenant_id: Tenant UUID for scoping.
            module_name: Name of the module.
            module_version: Module version string.
            security_level: Target FIPS 140-2 security level.
            algorithm_verification: Output from verify_algorithms.
            key_validation: Output from validate_key_lengths.
            rng_check: Output from check_rng_compliance.
            self_tests_passed: Whether module self-tests passed.

        Returns:
            FIPS 140-2 compliance certificate dict.
        """
        algo_compliant = algorithm_verification.get("fips_compliant", False)
        key_compliant = key_validation.get("fips_compliant", False)
        rng_compliant = rng_check.get("fips_compliant", False)

        overall_compliant = algo_compliant and key_compliant and rng_compliant and self_tests_passed

        findings_summary: list[str] = []
        if not algo_compliant:
            count = algorithm_verification.get("non_approved_count", 0)
            findings_summary.append(f"{count} non-approved cryptographic algorithm(s) detected")
        if not key_compliant:
            count = key_validation.get("non_compliant_count", 0)
            findings_summary.append(f"{count} key configuration(s) below minimum length")
        if not rng_compliant:
            count = rng_check.get("non_compliant_count", 0)
            findings_summary.append(f"{count} non-compliant DRBG implementation(s)")
        if not self_tests_passed:
            findings_summary.append("Module self-tests did not pass")

        certificate = {
            "certificate_id": str(uuid.uuid4()),
            "tenant_id": str(tenant_id),
            "module_name": module_name,
            "module_version": module_version,
            "target_security_level": security_level,
            "fips_standard": "FIPS 140-2",
            "validation_components": {
                "algorithm_verification": {"compliant": algo_compliant},
                "key_length_validation": {"compliant": key_compliant},
                "rng_compliance": {"compliant": rng_compliant},
                "self_tests": {"passed": self_tests_passed},
            },
            "overall_compliant": overall_compliant,
            "compliance_status": "COMPLIANT" if overall_compliant else "NON-COMPLIANT",
            "findings_summary": findings_summary,
            "remediation_required": not overall_compliant,
            "cmvp_submission_guidance": (
                "Submit to NIST CMVP for formal FIPS 140-2 certificate"
                if security_level >= 2
                else "Level 1 validation — internal documentation sufficient"
            ),
            "certificate_valid_until": None,  # Assigned after formal CMVP review
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generated_by": "aumos-finserv-overlay FIPS Validator",
        }

        logger.info(
            "FIPS 140-2 compliance certificate generated",
            module_name=module_name,
            security_level=security_level,
            overall_compliant=overall_compliant,
            findings_count=len(findings_summary),
        )

        return certificate


__all__ = ["FIPSValidator"]
