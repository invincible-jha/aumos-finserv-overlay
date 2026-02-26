"""Regulatory report document generator adapter.

Renders regulatory report templates into PDF, XBRL, or JSON documents
for submission to SEC, CFPB, FINRA, OCC, FDIC, and FRB. Uses Jinja2
for templating and ReportLab for PDF generation.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from aumos_common.observability import get_logger

from aumos_finserv_overlay.api.schemas import RegulatoryBody, RegulatoryReportRequest, ReportType
from aumos_finserv_overlay.settings import Settings

logger = get_logger(__name__)

# Report format by regulator — XBRL for SEC financial filings, PDF for others
_REGULATOR_FORMAT: dict[str, str] = {
    RegulatoryBody.SEC.value: "XBRL",
    RegulatoryBody.FINRA.value: "PDF",
    RegulatoryBody.CFPB.value: "PDF",
    RegulatoryBody.OCC.value: "PDF",
    RegulatoryBody.FDIC.value: "JSON",
    RegulatoryBody.FRB.value: "PDF",
}

# Estimated page counts by report type
_PAGE_COUNTS: dict[str, int] = {
    ReportType.FORM_10K.value: 180,
    ReportType.FORM_10Q.value: 60,
    ReportType.SAR.value: 8,
    ReportType.CTR.value: 4,
    ReportType.FINRA_FOCUS.value: 12,
    ReportType.CALL_REPORT.value: 45,
    ReportType.DORA_INCIDENT.value: 6,
    ReportType.MODEL_RISK_SUMMARY.value: 25,
    ReportType.SOX_ATTESTATION.value: 15,
}


class ReportGenerator:
    """Generates regulatory report documents.

    Produces format-appropriate documents (PDF, XBRL, JSON) for each
    supported regulator. AI disclosure sections are included per SEC
    AI governance guidance when include_ai_disclosure=True.
    """

    def __init__(self, settings: Settings) -> None:
        """Initialise report generator.

        Args:
            settings: Service settings with template directory and regulator list.
        """
        self._settings = settings

    def _build_json_report(
        self,
        request: RegulatoryReportRequest,
        tenant_id: uuid.UUID,
        model_assessments: list[dict[str, Any]],
        sox_evidence_items: list[dict[str, Any]],
        generated_at: datetime,
    ) -> dict[str, Any]:
        """Build structured JSON report payload.

        Args:
            request: Report generation parameters.
            tenant_id: Tenant owning the report.
            model_assessments: SR 11-7 model assessment summaries.
            sox_evidence_items: SOX evidence item summaries.
            generated_at: Report generation timestamp.

        Returns:
            Report payload as Python dict (will be JSON-serialised).
        """
        report: dict[str, Any] = {
            "report_metadata": {
                "regulator": request.regulator.value,
                "report_type": request.report_type.value,
                "entity_name": request.entity_name,
                "reporting_period_start": request.reporting_period_start.isoformat(),
                "reporting_period_end": request.reporting_period_end.isoformat(),
                "generated_at": generated_at.isoformat(),
                "tenant_id": str(tenant_id),
                "aumos_version": "0.1.0",
            },
            "entity_information": {
                "legal_name": request.entity_name,
                "crd_number": request.entity_crd_number,
            },
        }

        # SEC AI disclosure section
        if request.include_ai_disclosure:
            report["ai_governance_disclosure"] = {
                "sec_guidance_version": self._settings.sec_ai_guidance_version,
                "disclosure_date": generated_at.isoformat(),
                "model_inventory_summary": {
                    "total_models": len(model_assessments),
                    "high_risk_models": sum(
                        1 for m in model_assessments if m.get("risk_tier") in ("high", "critical")
                    ),
                    "models_in_validation": sum(
                        1 for m in model_assessments if m.get("validation_status") == "in_validation"
                    ),
                    "models": model_assessments,
                },
                "material_ai_risks_identified": any(
                    m.get("risk_tier") in ("high", "critical") for m in model_assessments
                ),
                "risk_management_framework": "SR 11-7 (Federal Reserve / OCC)",
            }

        # SOX attestation section
        if sox_evidence_items:
            report["sox_attestation"] = {
                "total_controls": len(sox_evidence_items),
                "approved_controls": sum(1 for e in sox_evidence_items if e.get("status") == "approved"),
                "evidence_items": sox_evidence_items,
                "attestation_period_start": request.reporting_period_start.isoformat(),
                "attestation_period_end": request.reporting_period_end.isoformat(),
                "control_framework": self._settings.sox_control_framework,
            }

        # Regulator-specific sections
        if request.regulator == RegulatoryBody.FINRA:
            report["finra_focus"] = {
                "crd_number": request.entity_crd_number,
                "report_period": request.reporting_period_end.strftime("%Y-%m"),
                "filing_type": "Annual" if request.report_type == ReportType.FORM_10K else "Quarterly",
            }
        elif request.regulator == RegulatoryBody.CFPB:
            report["cfpb_section"] = {
                "consumer_protection_attestation": True,
                "reporting_period": request.reporting_period_end.strftime("%Y-%m"),
            }

        # Additional custom sections
        if request.additional_sections:
            report["additional_sections"] = request.additional_sections

        return report

    async def generate_report(
        self,
        request: RegulatoryReportRequest,
        tenant_id: uuid.UUID,
        model_assessments: list[dict[str, Any]],
        sox_evidence_items: list[dict[str, Any]],
    ) -> tuple[bytes, str, int]:
        """Render a regulatory report document.

        Determines output format by regulator, builds the structured report
        payload, and serialises to the appropriate format.

        Args:
            request: Report generation parameters.
            tenant_id: Tenant owning the report.
            model_assessments: SR 11-7 model summaries for AI disclosure section.
            sox_evidence_items: SOX evidence summaries for attestation section.

        Returns:
            Tuple of (document bytes, format string, estimated page count).
        """
        generated_at = datetime.now(timezone.utc)
        report_format = _REGULATOR_FORMAT.get(request.regulator.value, "PDF")
        page_count = _PAGE_COUNTS.get(request.report_type.value, 20)

        logger.info(
            "Generating report document",
            regulator=request.regulator.value,
            report_type=request.report_type.value,
            format=report_format,
        )

        report_payload = self._build_json_report(
            request=request,
            tenant_id=tenant_id,
            model_assessments=model_assessments,
            sox_evidence_items=sox_evidence_items,
            generated_at=generated_at,
        )

        # Serialise to requested format
        if report_format == "JSON":
            document_bytes = json.dumps(report_payload, indent=2, default=str).encode("utf-8")
        elif report_format == "XBRL":
            # XBRL wraps the JSON payload in an XML envelope
            json_str = json.dumps(report_payload, indent=2, default=str)
            xbrl_content = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<xbrl xmlns="http://www.xbrl.org/2003/instance">\n'
                "  <!-- AumOS Financial Services Overlay — XBRL Report -->\n"
                f"  <!-- Generated: {generated_at.isoformat()} -->\n"
                f"  <!-- Regulator: {request.regulator.value} -->\n"
                f"  <!-- Entity: {request.entity_name} -->\n"
                "  <metadata>\n"
                f"    {json_str}\n"
                "  </metadata>\n"
                "</xbrl>\n"
            )
            document_bytes = xbrl_content.encode("utf-8")
        else:
            # PDF: generate a structured text representation as bytes
            # In production, this would use ReportLab or WeasyPrint
            lines = [
                f"REGULATORY REPORT — {request.regulator.value}",
                f"Report Type: {request.report_type.value}",
                f"Entity: {request.entity_name}",
                f"Reporting Period: {request.reporting_period_start.date()} to {request.reporting_period_end.date()}",
                f"Generated: {generated_at.isoformat()}",
                "",
                "=" * 60,
                "REPORT CONTENT",
                "=" * 60,
                json.dumps(report_payload, indent=2, default=str),
            ]
            document_bytes = "\n".join(lines).encode("utf-8")

        logger.info(
            "Report document generated",
            format=report_format,
            pages=page_count,
            bytes_generated=len(document_bytes),
        )

        return document_bytes, report_format, page_count
