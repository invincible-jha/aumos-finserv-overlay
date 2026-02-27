"""SOX compliance adapter for aumos-finserv-overlay.

Implements SOX Section 302 and 404 evidence collection, control effectiveness
testing, deficiency classification, and audit trail generation aligned with
PCAOB / COSO Internal Control framework requirements.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# SOX control area to COSO component mapping
_COSO_COMPONENT_MAP: dict[str, str] = {
    "ITGC": "Control Environment",
    "FINANCIAL_REPORTING": "Control Activities",
    "DISCLOSURE_CONTROLS": "Information and Communication",
    "ENTITY_LEVEL": "Risk Assessment",
    "OPERATIONS": "Monitoring Activities",
}

# SOX 302/404 article mapping by control area
_SOX_ARTICLE_MAP: dict[str, list[str]] = {
    "ITGC": ["SOX-302", "SOX-404(a)", "SOX-404(b)"],
    "FINANCIAL_REPORTING": ["SOX-302", "SOX-404(a)", "SOX-404(b)"],
    "DISCLOSURE_CONTROLS": ["SOX-302", "SOX-409"],
    "ENTITY_LEVEL": ["SOX-404(a)", "SOX-404(b)"],
    "OPERATIONS": ["SOX-404(a)"],
}

# Control effectiveness rating thresholds (percentage of passing test steps)
_EFFECTIVENESS_THRESHOLDS = {
    "EFFECTIVE": 0.90,
    "DEFICIENCY": 0.70,
    "SIGNIFICANT_DEFICIENCY": 0.50,
    "MATERIAL_WEAKNESS": 0.0,
}

# Evidence types that satisfy PCAOB audit requirements
_PCAOB_ACCEPTED_EVIDENCE_TYPES = {
    "system_report",
    "screen_capture",
    "policy_document",
    "approval_log",
    "configuration_export",
    "reconciliation_report",
    "management_attestation",
    "third_party_confirmation",
}


class SOXComplianceAdapter:
    """Manages SOX evidence collection and control effectiveness testing.

    Implements PCAOB / COSO-aligned workflows for SOX Section 302 and
    404 attestation. Generates immutable, hash-chained audit trails and
    supports both management assertion and independent auditor review.
    """

    def __init__(self) -> None:
        """Initialize SOX compliance adapter."""
        self._audit_chain_hash: str = ""

    def define_control(
        self,
        control_id: str,
        control_area: str,
        control_description: str,
        control_owner: str,
        is_key_control: bool,
        frequency: str,
        automated: bool,
        review_period_start: datetime,
        review_period_end: datetime,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Define a SOX internal control with COSO framework alignment.

        Generates a structured control definition including SOX article mapping,
        COSO component classification, and testing requirements.

        Args:
            control_id: Unique control identifier (e.g., "ITGC-001").
            control_area: Control area (ITGC, FINANCIAL_REPORTING, etc.).
            control_description: Narrative description of the control.
            control_owner: Name and title of the control owner.
            is_key_control: Whether this is a key control for SOX 404 purposes.
            frequency: Control execution frequency (daily/weekly/monthly/quarterly/annual).
            automated: Whether the control is fully automated.
            review_period_start: Beginning of the review period.
            review_period_end: End of the review period.
            metadata: Optional additional metadata.

        Returns:
            Structured control definition dict with COSO and SOX mappings.
        """
        coso_component = _COSO_COMPONENT_MAP.get(control_area, "Control Activities")
        sox_articles = _SOX_ARTICLE_MAP.get(control_area, ["SOX-404(a)"])
        control_type = "Preventive" if automated else "Detective"

        review_days = (review_period_end - review_period_start).days
        if review_days < 90:
            coverage_assessment = "Insufficient — minimum 90-day review period required"
        elif review_days < 180:
            coverage_assessment = "Partial — consider extending to semi-annual period"
        else:
            coverage_assessment = "Adequate"

        control_definition = {
            "control_id": control_id,
            "control_area": control_area,
            "control_description": control_description,
            "control_owner": control_owner,
            "is_key_control": is_key_control,
            "frequency": frequency,
            "automated": automated,
            "control_type": control_type,
            "coso_component": coso_component,
            "sox_articles": sox_articles,
            "review_period_start": review_period_start.isoformat(),
            "review_period_end": review_period_end.isoformat(),
            "review_period_days": review_days,
            "coverage_assessment": coverage_assessment,
            "testing_required": is_key_control,
            "pcaob_documentation_required": is_key_control and not automated,
            "defined_at": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata or {},
        }

        logger.info(
            "SOX control defined",
            control_id=control_id,
            control_area=control_area,
            is_key_control=is_key_control,
            sox_articles=sox_articles,
        )

        return control_definition

    def collect_evidence(
        self,
        control_id: str,
        control_area: str,
        evidence_description: str,
        evidence_artifacts: list[str],
        evidence_type: str,
        review_period_start: datetime,
        review_period_end: datetime,
        control_owner: str,
        is_key_control: bool,
    ) -> dict[str, Any]:
        """Automate evidence collection for a SOX control.

        Validates evidence against PCAOB acceptance criteria, generates
        an evidence package with hash-based integrity protection, and
        returns collection metadata for audit trail purposes.

        Args:
            control_id: Control identifier the evidence relates to.
            control_area: Area classification of the control.
            evidence_description: Narrative description of the evidence.
            evidence_artifacts: List of artifact URIs or identifiers.
            evidence_type: Type of evidence (must be PCAOB-accepted).
            review_period_start: Start of the review period covered.
            review_period_end: End of the review period covered.
            control_owner: Owner responsible for the control.
            is_key_control: Whether this is a key control.

        Returns:
            Evidence collection package dict with integrity hash.
        """
        pcaob_accepted = evidence_type in _PCAOB_ACCEPTED_EVIDENCE_TYPES
        sox_articles = _SOX_ARTICLE_MAP.get(control_area, ["SOX-404(a)"])

        evidence_package = {
            "control_id": control_id,
            "control_area": control_area,
            "evidence_description": evidence_description,
            "evidence_artifacts": evidence_artifacts,
            "evidence_type": evidence_type,
            "artifact_count": len(evidence_artifacts),
            "pcaob_accepted": pcaob_accepted,
            "sox_articles": sox_articles,
            "review_period_start": review_period_start.isoformat(),
            "review_period_end": review_period_end.isoformat(),
            "control_owner": control_owner,
            "is_key_control": is_key_control,
            "collected_at": datetime.now(timezone.utc).isoformat(),
        }

        if not pcaob_accepted:
            evidence_package["pcaob_warning"] = (
                f"Evidence type '{evidence_type}' is not in PCAOB-accepted types. "
                "Supplementary evidence may be required for external audit."
            )

        if len(evidence_artifacts) == 0:
            evidence_package["artifact_warning"] = (
                "No evidence artifacts provided. At least one artifact URI is required."
            )

        # Generate integrity hash for tamper detection
        evidence_str = json.dumps(evidence_package, sort_keys=True)
        evidence_hash = hashlib.sha256(evidence_str.encode()).hexdigest()
        evidence_package["integrity_hash"] = evidence_hash

        logger.info(
            "SOX evidence collected",
            control_id=control_id,
            evidence_type=evidence_type,
            artifact_count=len(evidence_artifacts),
            pcaob_accepted=pcaob_accepted,
        )

        return evidence_package

    def test_control_effectiveness(
        self,
        control_id: str,
        control_area: str,
        is_key_control: bool,
        test_steps: list[dict[str, Any]],
        population_size: int,
        sample_size: int,
        automated_control: bool,
    ) -> dict[str, Any]:
        """Test the effectiveness of a SOX internal control.

        Evaluates test step results against PCAOB effectiveness thresholds
        to classify the control as effective, deficient, significantly deficient,
        or a material weakness.

        Args:
            control_id: Control being tested.
            control_area: Area classification of the control.
            is_key_control: Whether this is a key control.
            test_steps: List of test step dicts with 'description' and 'passed' keys.
            population_size: Total population size for sampling.
            sample_size: Number of items sampled for testing.
            automated_control: Whether this is an automated control.

        Returns:
            Control effectiveness assessment dict with rating and findings.
        """
        if not test_steps:
            passing_rate = 0.0
        else:
            passing_steps = sum(1 for step in test_steps if step.get("passed", False))
            passing_rate = passing_steps / len(test_steps)

        # Determine effectiveness rating
        if passing_rate >= _EFFECTIVENESS_THRESHOLDS["EFFECTIVE"]:
            effectiveness_rating = "EFFECTIVE"
            deficiency_type = None
        elif passing_rate >= _EFFECTIVENESS_THRESHOLDS["DEFICIENCY"]:
            effectiveness_rating = "DEFICIENCY"
            deficiency_type = "Control Deficiency"
        elif passing_rate >= _EFFECTIVENESS_THRESHOLDS["SIGNIFICANT_DEFICIENCY"]:
            effectiveness_rating = "SIGNIFICANT_DEFICIENCY"
            deficiency_type = "Significant Deficiency" if not is_key_control else "Material Weakness (Key Control)"
        else:
            effectiveness_rating = "MATERIAL_WEAKNESS"
            deficiency_type = "Material Weakness"

        # PCAOB sampling adequacy check
        if population_size > 0:
            sampling_rate = sample_size / population_size
            if sampling_rate < 0.05 and population_size > 100:
                sampling_adequacy = "Insufficient — PCAOB requires minimum 5% or 60 items for large populations"
            else:
                sampling_adequacy = "Adequate"
        else:
            sampling_adequacy = "Not applicable — no population defined"

        failed_steps = [
            step for step in test_steps if not step.get("passed", False)
        ]

        remediation_required = effectiveness_rating in ("DEFICIENCY", "SIGNIFICANT_DEFICIENCY", "MATERIAL_WEAKNESS")
        management_disclosure_required = effectiveness_rating == "MATERIAL_WEAKNESS" or (
            effectiveness_rating == "SIGNIFICANT_DEFICIENCY" and is_key_control
        )

        result = {
            "control_id": control_id,
            "control_area": control_area,
            "is_key_control": is_key_control,
            "automated_control": automated_control,
            "test_steps_total": len(test_steps),
            "test_steps_passed": sum(1 for s in test_steps if s.get("passed", False)),
            "test_steps_failed": len(failed_steps),
            "passing_rate": round(passing_rate, 4),
            "population_size": population_size,
            "sample_size": sample_size,
            "sampling_adequacy": sampling_adequacy,
            "effectiveness_rating": effectiveness_rating,
            "deficiency_type": deficiency_type,
            "remediation_required": remediation_required,
            "management_disclosure_required": management_disclosure_required,
            "failed_test_steps": [s.get("description", "") for s in failed_steps],
            "tested_at": datetime.now(timezone.utc).isoformat(),
            "sox_articles": _SOX_ARTICLE_MAP.get(control_area, ["SOX-404(a)"]),
        }

        logger.info(
            "SOX control effectiveness tested",
            control_id=control_id,
            effectiveness_rating=effectiveness_rating,
            passing_rate=passing_rate,
            remediation_required=remediation_required,
        )

        return result

    def classify_deficiency(
        self,
        control_id: str,
        deficiency_description: str,
        financial_statement_impact: str,
        is_key_control: bool,
        compensating_controls: list[str],
        management_override_risk: bool,
    ) -> dict[str, Any]:
        """Classify a SOX control deficiency per PCAOB AS 2201 standards.

        Evaluates deficiency severity based on financial statement impact,
        key control status, compensating controls, and management override risk
        to classify as control deficiency, significant deficiency, or material weakness.

        Args:
            control_id: Control with the identified deficiency.
            deficiency_description: Description of the deficiency.
            financial_statement_impact: Impact on financial statement assertions.
            is_key_control: Whether this is a key control for SOX 404.
            compensating_controls: List of compensating control identifiers.
            management_override_risk: Whether management override risk exists.

        Returns:
            Deficiency classification dict with severity and disclosure requirements.
        """
        has_compensating_controls = len(compensating_controls) > 0

        # PCAOB AS 2201 severity classification logic
        if management_override_risk or (is_key_control and not has_compensating_controls):
            severity = "MATERIAL_WEAKNESS"
            disclosure_required = True
            disclosure_target = "SEC Form 10-K, Management Report on Internal Controls"
            auditor_communication_required = True
        elif is_key_control and has_compensating_controls:
            severity = "SIGNIFICANT_DEFICIENCY"
            disclosure_required = True
            disclosure_target = "Audit Committee"
            auditor_communication_required = True
        else:
            severity = "CONTROL_DEFICIENCY"
            disclosure_required = False
            disclosure_target = None
            auditor_communication_required = False

        remediation_timeline_days = {
            "MATERIAL_WEAKNESS": 90,
            "SIGNIFICANT_DEFICIENCY": 180,
            "CONTROL_DEFICIENCY": 365,
        }.get(severity, 365)

        classification = {
            "control_id": control_id,
            "deficiency_description": deficiency_description,
            "financial_statement_impact": financial_statement_impact,
            "is_key_control": is_key_control,
            "compensating_controls": compensating_controls,
            "has_compensating_controls": has_compensating_controls,
            "management_override_risk": management_override_risk,
            "severity": severity,
            "disclosure_required": disclosure_required,
            "disclosure_target": disclosure_target,
            "auditor_communication_required": auditor_communication_required,
            "remediation_timeline_days": remediation_timeline_days,
            "pcaob_standard": "AS 2201 — An Audit of Internal Control Over Financial Reporting",
            "classified_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "SOX deficiency classified",
            control_id=control_id,
            severity=severity,
            disclosure_required=disclosure_required,
            management_override_risk=management_override_risk,
        )

        return classification

    def generate_management_assertion(
        self,
        tenant_id: uuid.UUID,
        entity_name: str,
        fiscal_year_end: datetime,
        controls_effective: int,
        controls_deficient: int,
        controls_material_weakness: int,
        coso_framework_version: str = "2013",
    ) -> dict[str, Any]:
        """Generate a SOX 302/404 management assertion document.

        Produces a structured management assertion suitable for inclusion
        in the annual SEC filing, consistent with PCAOB AS 2201 requirements.

        Args:
            tenant_id: Tenant UUID for record identification.
            entity_name: Legal name of the reporting entity.
            fiscal_year_end: Fiscal year end date.
            controls_effective: Count of effective controls.
            controls_deficient: Count of deficient controls.
            controls_material_weakness: Count of material weaknesses.
            coso_framework_version: COSO Internal Control framework version.

        Returns:
            Management assertion dict with SOX 302 and 404 sections.
        """
        total_controls = controls_effective + controls_deficient + controls_material_weakness
        effectiveness_rate = (controls_effective / total_controls * 100) if total_controls > 0 else 0.0

        # Determine overall assertion
        if controls_material_weakness > 0:
            overall_opinion = "ADVERSE"
            icfr_effective = False
            caveat = f"{controls_material_weakness} material weakness(es) identified. "
            "Internal control over financial reporting is NOT effective."
        elif controls_deficient > 0:
            overall_opinion = "QUALIFIED"
            icfr_effective = True
            caveat = f"{controls_deficient} significant deficiency(ies) disclosed to audit committee."
        else:
            overall_opinion = "UNQUALIFIED"
            icfr_effective = True
            caveat = None

        assertion = {
            "assertion_id": str(uuid.uuid4()),
            "tenant_id": str(tenant_id),
            "entity_name": entity_name,
            "fiscal_year_end": fiscal_year_end.isoformat(),
            "coso_framework": f"COSO Internal Control — Integrated Framework ({coso_framework_version})",
            "sox_302_assertion": {
                "section": "SOX Section 302 — Corporate Responsibility for Financial Reports",
                "ceo_cfo_certification": "Management has evaluated the effectiveness of disclosure controls and procedures",
                "material_changes_disclosed": True,
                "significant_deficiencies_disclosed": controls_deficient > 0,
                "fraud_disclosure": False,
            },
            "sox_404_assertion": {
                "section": "SOX Section 404 — Management Assessment of Internal Controls",
                "management_report_included": True,
                "icfr_framework": f"COSO {coso_framework_version}",
                "icfr_effective": icfr_effective,
                "overall_opinion": overall_opinion,
                "caveat": caveat,
                "total_controls_assessed": total_controls,
                "effective_controls": controls_effective,
                "deficient_controls": controls_deficient,
                "material_weaknesses": controls_material_weakness,
                "effectiveness_rate_pct": round(effectiveness_rate, 2),
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "attestation_period_end": fiscal_year_end.isoformat(),
            "document_version": "1.0",
        }

        logger.info(
            "SOX management assertion generated",
            tenant_id=str(tenant_id),
            entity_name=entity_name,
            overall_opinion=overall_opinion,
            icfr_effective=icfr_effective,
            material_weaknesses=controls_material_weakness,
        )

        return assertion

    def generate_audit_trail(
        self,
        tenant_id: uuid.UUID,
        evidence_records: list[dict[str, Any]],
        fiscal_year: int,
    ) -> dict[str, Any]:
        """Generate an immutable hash-chained SOX audit trail.

        Creates a cryptographically linked chain of evidence records
        providing tamper-evident documentation for PCAOB review and
        supporting 7-year retention requirements.

        Args:
            tenant_id: Tenant UUID for scoping.
            evidence_records: List of evidence record dicts to chain.
            fiscal_year: Fiscal year the audit trail covers.

        Returns:
            Audit trail dict with hash chain and metadata.
        """
        chain: list[dict[str, Any]] = []
        previous_hash = "GENESIS"

        for index, record in enumerate(evidence_records):
            record_data = json.dumps(
                {
                    "index": index,
                    "previous_hash": previous_hash,
                    "control_id": record.get("control_id", ""),
                    "evidence_type": record.get("evidence_type", ""),
                    "collected_at": record.get("collected_at", ""),
                    "integrity_hash": record.get("integrity_hash", ""),
                },
                sort_keys=True,
            )
            current_hash = hashlib.sha256(record_data.encode()).hexdigest()

            chain.append(
                {
                    "chain_index": index,
                    "control_id": record.get("control_id", ""),
                    "evidence_type": record.get("evidence_type", ""),
                    "previous_hash": previous_hash,
                    "current_hash": current_hash,
                    "chained_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            previous_hash = current_hash

        audit_trail = {
            "audit_trail_id": str(uuid.uuid4()),
            "tenant_id": str(tenant_id),
            "fiscal_year": fiscal_year,
            "chain_length": len(chain),
            "genesis_hash": "GENESIS",
            "terminal_hash": previous_hash,
            "chain": chain,
            "retention_requirement_years": 7,
            "retention_expiry_year": fiscal_year + 7,
            "pcaob_compliant": True,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "SOX audit trail generated",
            tenant_id=str(tenant_id),
            fiscal_year=fiscal_year,
            chain_length=len(chain),
            terminal_hash=previous_hash[:16] + "...",
        )

        return audit_trail

    def map_sox_articles(
        self,
        control_areas: list[str],
        include_management_assertion: bool,
        include_auditor_attestation: bool,
    ) -> dict[str, Any]:
        """Map control areas to their applicable SOX article requirements.

        Generates a complete SOX article mapping showing which sections of
        the Sarbanes-Oxley Act apply to each control area, supporting
        attestation package preparation.

        Args:
            control_areas: List of control area identifiers.
            include_management_assertion: Include Section 302 management certification.
            include_auditor_attestation: Include Section 404(b) auditor attestation.

        Returns:
            SOX article mapping dict with compliance requirements per area.
        """
        article_mapping: dict[str, Any] = {
            "sox_302_applicable": include_management_assertion,
            "sox_404a_applicable": True,
            "sox_404b_applicable": include_auditor_attestation,
            "control_area_mapping": {},
        }

        all_articles: set[str] = set()
        for area in control_areas:
            articles = _SOX_ARTICLE_MAP.get(area, ["SOX-404(a)"])
            article_mapping["control_area_mapping"][area] = {
                "applicable_articles": articles,
                "coso_component": _COSO_COMPONENT_MAP.get(area, "Control Activities"),
                "key_control_required": area in ("ITGC", "FINANCIAL_REPORTING"),
            }
            all_articles.update(articles)

        article_mapping["all_applicable_articles"] = sorted(all_articles)
        article_mapping["compliance_scope"] = {
            "total_control_areas": len(control_areas),
            "sox_302_scope": include_management_assertion,
            "sox_404a_scope": True,
            "sox_404b_scope": include_auditor_attestation,
            "pcaob_standard": "PCAOB AS 2201",
            "coso_framework": "COSO 2013",
        }

        logger.info(
            "SOX article mapping completed",
            control_areas_mapped=len(control_areas),
            total_articles=len(all_articles),
        )

        return article_mapping


__all__ = ["SOXComplianceAdapter"]
