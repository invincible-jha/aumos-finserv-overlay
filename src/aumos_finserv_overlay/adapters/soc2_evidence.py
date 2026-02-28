"""SOC2 Type II audit evidence service.

GAP-297: SOC2 Type II Audit Evidence.
"""
from __future__ import annotations

import uuid
from datetime import date, datetime, timezone
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# AICPA Trust Services Criteria control mapping
# Maps TSC control IDs to relevant activity categories
TSC_CONTROL_MAP: dict[str, list[str]] = {
    "CC6.1": ["logical_access", "authentication", "mfa", "rbac"],
    "CC6.2": ["user_provisioning", "deprovisioning", "access_review"],
    "CC7.2": ["system_monitoring", "alert_review", "incident_detection"],
    "CC8.1": ["change_management", "deployment_approval", "rollback"],
    "A1.1": ["availability_monitoring", "rpo_rto", "capacity_planning"],
    "PI1.1": ["data_processing_integrity", "validation_errors", "reconciliation"],
    "C1.1": ["data_classification", "confidentiality_controls", "encryption"],
    "P1.1": ["privacy_notice", "consent_management", "data_subject_rights"],
}

# TSC category names per AICPA Trust Services Criteria 2017
TSC_CATEGORY_NAMES: dict[str, str] = {
    "CC": "Common Criteria — Security",
    "A": "Availability",
    "C": "Confidentiality",
    "PI": "Processing Integrity",
    "P": "Privacy",
}


class SOC2EvidenceService:
    """Maps AumOS platform activities to AICPA Trust Services Criteria controls.

    Generates audit-ready evidence packages for SOC2 Type II audit periods.
    Extends the SOX evidence infrastructure with TSC-specific control mappings.
    Big Four audit firms accept the JSON output format used here.
    """

    def map_activity_to_tsc(self, activity_type: str) -> list[str]:
        """Map an AumOS activity type to applicable TSC control IDs.

        Args:
            activity_type: Activity category (e.g. 'logical_access', 'mfa').

        Returns:
            List of TSC control IDs that cover this activity.
        """
        return [
            control_id
            for control_id, activities in TSC_CONTROL_MAP.items()
            if activity_type in activities
        ]

    def generate_evidence_package(
        self,
        tenant_id: uuid.UUID,
        audit_period_start: date,
        audit_period_end: date,
        evidence_items: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Generate a SOC2 Type II audit evidence package.

        Maps each evidence item to its TSC control category and formats
        the package for submission to Big Four audit firms.

        Args:
            tenant_id: Tenant UUID for scoping.
            audit_period_start: Start of the Type II audit period.
            audit_period_end: End of the Type II audit period.
            evidence_items: List of evidence records with type and payload.

        Returns:
            Structured SOC2 evidence package dict with AICPA schema.
        """
        tsc_buckets: dict[str, list[dict]] = {ctrl: [] for ctrl in TSC_CONTROL_MAP}

        for item in evidence_items:
            activity_type = item.get("evidence_type", "")
            matched_controls = self.map_activity_to_tsc(activity_type)
            for control_id in matched_controls:
                tsc_buckets[control_id].append(
                    {
                        "evidence_id": str(item.get("id", uuid.uuid4())),
                        "evidence_type": activity_type,
                        "evidence_payload": item.get("evidence_payload", {}),
                        "collected_at": item.get("created_at", datetime.now(timezone.utc).isoformat()),
                        "tsc_control_id": control_id,
                        "sox_evidence_id": item.get("sox_evidence_id"),
                    }
                )
                logger.debug(
                    "soc2_evidence_mapped",
                    control_id=control_id,
                    activity_type=activity_type,
                )

        controls_with_evidence = [ctrl for ctrl, items in tsc_buckets.items() if items]
        coverage_pct = len(controls_with_evidence) / len(TSC_CONTROL_MAP) if TSC_CONTROL_MAP else 0.0

        return {
            "schema_version": "AICPA-TSC-2017",
            "package_id": str(uuid.uuid4()),
            "tenant_id": str(tenant_id),
            "audit_period": {
                "start": audit_period_start.isoformat(),
                "end": audit_period_end.isoformat(),
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tsc_coverage": {
                "total_controls": len(TSC_CONTROL_MAP),
                "controls_with_evidence": len(controls_with_evidence),
                "coverage_pct": round(coverage_pct * 100, 1),
            },
            "controls": {
                control_id: {
                    "tsc_category": self._get_tsc_category(control_id),
                    "evidence_count": len(items),
                    "evidence": items,
                }
                for control_id, items in tsc_buckets.items()
            },
        }

    @staticmethod
    def _get_tsc_category(control_id: str) -> str:
        """Map a TSC control ID to its category name."""
        prefix = control_id.split(".")[0].rstrip("0123456789") if "." in control_id else control_id[:2]
        return TSC_CATEGORY_NAMES.get(prefix, "Unknown")
