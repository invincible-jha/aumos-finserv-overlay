"""FastAPI router for aumos-finserv-overlay.

All routes are thin — they validate inputs, extract auth context,
delegate to services, and return typed responses.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from aumos_common.auth import get_current_tenant, get_current_user
from aumos_common.database import get_db_session
from aumos_common.errors import NotFoundError
from aumos_common.observability import get_logger
from aumos_common.pagination import PageRequest

from aumos_finserv_overlay.adapters.kafka import FinServEventPublisher
from aumos_finserv_overlay.adapters.report_generator import ReportGenerator
from aumos_finserv_overlay.adapters.repositories import (
    DORARepository,
    ModelRiskRepository,
    PCIDSSRepository,
    RegulatoryReportRepository,
    SOXEvidenceRepository,
    SyntheticTransactionRepository,
)
from aumos_finserv_overlay.adapters.transaction_generator import TransactionGenerator
from aumos_finserv_overlay.api.schemas import (
    DORAStatusResponse,
    ModelRiskAssessmentRequest,
    ModelRiskAssessmentResponse,
    PCIDSSScanRequest,
    PCIDSSScanResponse,
    RegulatoryReportListResponse,
    RegulatoryReportRequest,
    RegulatoryReportResponse,
    SOXEvidenceRequest,
    SOXEvidenceResponse,
    SOXStatusResponse,
    SyntheticTransactionRequest,
    SyntheticTransactionResponse,
)
from aumos_finserv_overlay.core.services import (
    DORAService,
    ModelRiskService,
    PCIDSSService,
    RegulatoryReportService,
    SOXComplianceService,
    SyntheticTransactionService,
)
from aumos_finserv_overlay.settings import Settings

logger = get_logger(__name__)
settings = Settings()

router = APIRouter(tags=["finserv"])


# ============================================================================
# Dependency factories
# ============================================================================


def get_sox_service(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> SOXComplianceService:
    """Build SOXComplianceService with injected dependencies."""
    return SOXComplianceService(
        sox_repository=SOXEvidenceRepository(session),
        event_publisher=FinServEventPublisher(),
        settings=settings,
    )


def get_model_risk_service(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> ModelRiskService:
    """Build ModelRiskService with injected dependencies."""
    return ModelRiskService(
        model_risk_repository=ModelRiskRepository(session),
        event_publisher=FinServEventPublisher(),
        settings=settings,
    )


def get_pci_service(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> PCIDSSService:
    """Build PCIDSSService with injected dependencies."""
    return PCIDSSService(
        pci_repository=PCIDSSRepository(session),
        event_publisher=FinServEventPublisher(),
        settings=settings,
    )


def get_dora_service(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> DORAService:
    """Build DORAService with injected dependencies."""
    return DORAService(
        dora_repository=DORARepository(session),
        event_publisher=FinServEventPublisher(),
        settings=settings,
    )


def get_synth_service(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> SyntheticTransactionService:
    """Build SyntheticTransactionService with injected dependencies."""
    return SyntheticTransactionService(
        transaction_repository=SyntheticTransactionRepository(session),
        transaction_generator=TransactionGenerator(),
        event_publisher=FinServEventPublisher(),
        settings=settings,
    )


def get_report_service(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> RegulatoryReportService:
    """Build RegulatoryReportService with injected dependencies."""
    return RegulatoryReportService(
        report_repository=RegulatoryReportRepository(session),
        model_risk_repository=ModelRiskRepository(session),
        sox_repository=SOXEvidenceRepository(session),
        report_generator=ReportGenerator(settings),
        event_publisher=FinServEventPublisher(),
        settings=settings,
    )


# ============================================================================
# SOX Endpoints
# ============================================================================


@router.post(
    "/finserv/sox/evidence",
    response_model=SOXEvidenceResponse,
    summary="Collect SOX compliance evidence",
    description=(
        "Submit SOX internal control evidence for a specific control. "
        "Evidence is immutably archived for 7 years per PCAOB requirements. "
        "Initial status is 'pending_review'."
    ),
)
async def collect_sox_evidence(
    request: SOXEvidenceRequest,
    service: Annotated[SOXComplianceService, Depends(get_sox_service)],
    tenant: Annotated[uuid.UUID, Depends(get_current_tenant)],
) -> SOXEvidenceResponse:
    """Collect SOX compliance evidence for a control."""
    return await service.collect_evidence(request=request, tenant_id=tenant)


@router.get(
    "/finserv/sox/status",
    response_model=SOXStatusResponse,
    summary="SOX compliance status summary",
    description=(
        "Retrieve an aggregated SOX compliance status for the tenant, including "
        "control counts, deficiency tallies, and management attestation readiness."
    ),
)
async def get_sox_status(
    service: Annotated[SOXComplianceService, Depends(get_sox_service)],
    tenant: Annotated[uuid.UUID, Depends(get_current_tenant)],
) -> SOXStatusResponse:
    """Get SOX compliance status summary for a tenant."""
    return await service.get_status(tenant_id=tenant)


# ============================================================================
# SR 11-7 Model Risk Endpoints
# ============================================================================


@router.post(
    "/finserv/model-risk/assess",
    response_model=ModelRiskAssessmentResponse,
    summary="Perform SR 11-7 model risk assessment",
    description=(
        "Submit a model for SR 11-7 risk assessment. Returns risk tier (low/medium/high/critical), "
        "composite risk score, independent validation requirement, and recommended actions."
    ),
)
async def assess_model_risk(
    request: ModelRiskAssessmentRequest,
    service: Annotated[ModelRiskService, Depends(get_model_risk_service)],
    tenant: Annotated[uuid.UUID, Depends(get_current_tenant)],
) -> ModelRiskAssessmentResponse:
    """Perform an SR 11-7 model risk assessment."""
    return await service.assess_model(request=request, tenant_id=tenant)


@router.get(
    "/finserv/model-risk/{assessment_id}",
    response_model=ModelRiskAssessmentResponse,
    summary="Get model risk assessment detail",
    description="Retrieve a specific SR 11-7 model risk assessment by ID.",
)
async def get_model_risk_assessment(
    assessment_id: uuid.UUID,
    service: Annotated[ModelRiskService, Depends(get_model_risk_service)],
    tenant: Annotated[uuid.UUID, Depends(get_current_tenant)],
) -> ModelRiskAssessmentResponse:
    """Retrieve an SR 11-7 model risk assessment by ID."""
    return await service.get_assessment(assessment_id=assessment_id, tenant_id=tenant)


# ============================================================================
# PCI DSS Endpoints
# ============================================================================


@router.post(
    "/finserv/pci-dss/scan",
    response_model=PCIDSSScanResponse,
    summary="Perform PCI DSS v4.0 control scan",
    description=(
        "Evaluate cardholder data environment controls against PCI DSS v4.0. "
        "Returns control-level results with status, evidence, and QSA-readiness indicator."
    ),
)
async def scan_pci_dss(
    request: PCIDSSScanRequest,
    service: Annotated[PCIDSSService, Depends(get_pci_service)],
    tenant: Annotated[uuid.UUID, Depends(get_current_tenant)],
) -> PCIDSSScanResponse:
    """Perform a PCI DSS v4.0 control compliance scan."""
    return await service.scan(request=request, tenant_id=tenant)


# ============================================================================
# DORA Endpoints
# ============================================================================


@router.get(
    "/finserv/dora/status",
    response_model=DORAStatusResponse,
    summary="DORA ICT resilience status",
    description=(
        "Retrieve the current DORA (Digital Operational Resilience Act) ICT resilience "
        "status for the tenant, including RTO/RPO compliance, testing programme status, "
        "and open compliance gaps."
    ),
)
async def get_dora_status(
    service: Annotated[DORAService, Depends(get_dora_service)],
    tenant: Annotated[uuid.UUID, Depends(get_current_tenant)],
) -> DORAStatusResponse:
    """Get DORA ICT operational resilience status for a tenant."""
    return await service.get_status(tenant_id=tenant)


# ============================================================================
# Synthetic Transaction Endpoints
# ============================================================================


@router.post(
    "/finserv/synth/transactions",
    response_model=SyntheticTransactionResponse,
    summary="Generate synthetic financial transactions",
    description=(
        "Generate a synthetic financial transaction dataset with configurable transaction types, "
        "fraud injection rates, amount distributions, and merchant data. "
        "Output is suitable for ML model training and fraud detection pipeline testing. "
        "PII is masked by default."
    ),
)
async def generate_synthetic_transactions(
    request: SyntheticTransactionRequest,
    service: Annotated[SyntheticTransactionService, Depends(get_synth_service)],
    tenant: Annotated[uuid.UUID, Depends(get_current_tenant)],
) -> SyntheticTransactionResponse:
    """Generate a synthetic financial transaction dataset."""
    return await service.generate(request=request, tenant_id=tenant)


# ============================================================================
# Regulatory Report Endpoints
# ============================================================================


@router.get(
    "/finserv/reports",
    response_model=RegulatoryReportListResponse,
    summary="List regulatory reports",
    description=(
        "List all regulatory reports generated for the tenant, optionally filtered "
        "by regulator (SEC, CFPB, FINRA, OCC, FDIC, FRB). Results are paginated."
    ),
)
async def list_regulatory_reports(
    service: Annotated[RegulatoryReportService, Depends(get_report_service)],
    tenant: Annotated[uuid.UUID, Depends(get_current_tenant)],
    regulator: str | None = None,
    page: int = 1,
    page_size: int = 20,
) -> RegulatoryReportListResponse:
    """List regulatory reports for a tenant."""
    page_request = PageRequest(page=page, page_size=page_size)
    return await service.list_reports(
        tenant_id=tenant,
        regulator=regulator,
        page_request=page_request,
    )


@router.post(
    "/finserv/reports/generate",
    response_model=RegulatoryReportResponse,
    summary="Generate regulatory report",
    description=(
        "Generate a regulator-specific compliance report (SEC Form 10-K/10-Q, FINRA FOCUS, "
        "CFPB, Call Report, DORA Incident, etc.). Optionally includes SEC AI disclosure "
        "sections referencing your SR 11-7 model inventory."
    ),
)
async def generate_regulatory_report(
    request: RegulatoryReportRequest,
    service: Annotated[RegulatoryReportService, Depends(get_report_service)],
    tenant: Annotated[uuid.UUID, Depends(get_current_tenant)],
) -> RegulatoryReportResponse:
    """Generate a regulatory report for a specific regulator and report type."""
    return await service.generate_report(request=request, tenant_id=tenant)
