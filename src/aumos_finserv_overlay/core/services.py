"""Core business logic services for aumos-finserv-overlay.

All services are stateless and receive their dependencies via constructor
injection. No framework dependencies are imported here — only domain logic.
"""

import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

from aumos_common.errors import NotFoundError, ValidationError
from aumos_common.events import EventPublisher
from aumos_common.observability import get_logger
from aumos_common.pagination import PageRequest, PageResponse

from aumos_finserv_overlay.adapters.repositories import (
    DORARepository,
    ModelRiskRepository,
    PCIDSSRepository,
    RegulatoryReportRepository,
    SOXEvidenceRepository,
    SyntheticTransactionRepository,
)
from aumos_finserv_overlay.adapters.report_generator import ReportGenerator
from aumos_finserv_overlay.adapters.transaction_generator import TransactionGenerator
from aumos_finserv_overlay.api.schemas import (
    DORAResilienceStatus,
    DORAStatusResponse,
    ModelRiskAssessmentRequest,
    ModelRiskAssessmentResponse,
    ModelRiskStatus,
    ModelRiskTier,
    PCIControlResult,
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
from aumos_finserv_overlay.core.models import (
    DORAAssessment,
    ModelRiskAssessment,
    PCIDSSControl,
    RegulatoryReport,
    SOXEvidence,
    SyntheticTransaction,
)
from aumos_finserv_overlay.settings import Settings

logger = get_logger(__name__)


class SOXComplianceService:
    """Manages SOX compliance evidence collection and status reporting.

    Implements PCAOB / COSO-aligned evidence workflows for Section 302
    and Section 404 attestation, with 7-year immutable evidence retention.
    """

    def __init__(
        self,
        sox_repository: SOXEvidenceRepository,
        event_publisher: EventPublisher,
        settings: Settings,
    ) -> None:
        """Initialize SOX compliance service.

        Args:
            sox_repository: Repository for SOX evidence persistence.
            event_publisher: Kafka event publisher.
            settings: Service settings.
        """
        self._repo = sox_repository
        self._publisher = event_publisher
        self._settings = settings

    async def collect_evidence(
        self,
        request: SOXEvidenceRequest,
        tenant_id: uuid.UUID,
    ) -> SOXEvidenceResponse:
        """Collect and persist SOX compliance evidence.

        Creates an immutable evidence record with initial 'pending_review'
        status and publishes a Kafka event for audit trail purposes.

        Args:
            request: Evidence collection parameters.
            tenant_id: Tenant submitting the evidence.

        Returns:
            SOXEvidenceResponse with persisted evidence record.
        """
        logger.info(
            "Collecting SOX evidence",
            tenant_id=str(tenant_id),
            control_id=request.control_id,
            control_area=request.control_area,
        )

        evidence = SOXEvidence(
            tenant_id=tenant_id,
            control_id=request.control_id,
            control_area=request.control_area.value,
            control_description=request.control_description,
            evidence_description=request.evidence_description,
            evidence_artifacts=request.evidence_artifacts,
            control_owner=request.control_owner,
            review_period_start=request.review_period_start.isoformat(),
            review_period_end=request.review_period_end.isoformat(),
            is_key_control=request.is_key_control,
            status="pending_review",
            sox_metadata=request.metadata,
        )

        created = await self._repo.create(evidence)

        await self._publisher.publish(
            "finserv.sox.evidence.collected",
            {
                "tenant_id": str(tenant_id),
                "evidence_id": str(created.id),
                "control_id": request.control_id,
                "control_area": request.control_area.value,
                "is_key_control": request.is_key_control,
            },
        )

        logger.info(
            "SOX evidence collected",
            evidence_id=str(created.id),
            control_id=request.control_id,
        )
        return SOXEvidenceResponse.model_validate(created)

    async def get_status(self, tenant_id: uuid.UUID) -> SOXStatusResponse:
        """Compute SOX compliance status summary for a tenant.

        Aggregates evidence records to produce control counts, deficiency
        tallies, and attestation readiness indicator.

        Args:
            tenant_id: Tenant requesting status.

        Returns:
            SOXStatusResponse with aggregated compliance metrics.
        """
        all_evidence, total = await self._repo.list_by_tenant(
            tenant_id=tenant_id,
            control_area=None,
            page=1,
            page_size=10_000,
        )

        approved = sum(1 for e in all_evidence if e.status == "approved")
        pending_review = sum(1 for e in all_evidence if e.status == "pending_review")
        deficiencies = sum(1 for e in all_evidence if e.status == "deficiency")
        remediation_required = sum(1 for e in all_evidence if e.status == "remediation_required")

        # Material weakness threshold: any deficiency on a key control
        material_weaknesses = sum(
            1 for e in all_evidence if e.status == "deficiency" and e.is_key_control
        )

        compliance_pct = (approved / total * 100) if total > 0 else 0.0
        attestation_ready = deficiencies == 0 and material_weaknesses == 0 and pending_review == 0

        return SOXStatusResponse(
            tenant_id=tenant_id,
            total_controls=total,
            approved_controls=approved,
            pending_review=pending_review,
            deficiencies=deficiencies,
            material_weaknesses=material_weaknesses,
            compliance_percentage=round(compliance_pct, 2),
            last_updated=datetime.now(timezone.utc),
            attestation_ready=attestation_ready,
            open_remediation_items=remediation_required,
        )


class ModelRiskService:
    """Performs SR 11-7 model risk assessments.

    Implements Federal Reserve SR 11-7 / OCC 2011-12 guidance on model risk
    management: risk tiering, exposure scoring, independent validation
    tracking, and model inventory management.
    """

    def __init__(
        self,
        model_risk_repository: ModelRiskRepository,
        event_publisher: EventPublisher,
        settings: Settings,
    ) -> None:
        """Initialize model risk service.

        Args:
            model_risk_repository: Repository for assessment persistence.
            event_publisher: Kafka event publisher.
            settings: Service settings including risk thresholds.
        """
        self._repo = model_risk_repository
        self._publisher = event_publisher
        self._settings = settings

    def _compute_risk_score(self, request: ModelRiskAssessmentRequest) -> Decimal:
        """Compute composite SR 11-7 risk score (0.0–1.0).

        Weights factors: financial exposure, regulatory capital impact,
        customer-facing status, and number of known limitations.

        Args:
            request: Model risk assessment request.

        Returns:
            Composite risk score between 0.0 and 1.0.
        """
        score = Decimal("0.0")

        # Exposure component (max 0.40)
        exposure = float(request.estimated_annual_exposure)
        if exposure >= 1_000_000_000:
            score += Decimal("0.40")
        elif exposure >= 100_000_000:
            score += Decimal("0.30")
        elif exposure >= 10_000_000:
            score += Decimal("0.20")
        elif exposure >= 1_000_000:
            score += Decimal("0.10")

        # Regulatory capital impact (0.25)
        if request.regulatory_capital_impact:
            score += Decimal("0.25")

        # Customer-facing (0.20)
        if request.customer_facing:
            score += Decimal("0.20")

        # Known limitations penalty (max 0.15)
        limitations_count = len(request.known_limitations)
        score += Decimal(str(min(limitations_count * 0.03, 0.15)))

        return min(score, Decimal("1.0"))

    def _tier_from_score(self, score: Decimal) -> ModelRiskTier:
        """Map risk score to SR 11-7 risk tier.

        Args:
            score: Computed risk score 0.0–1.0.

        Returns:
            ModelRiskTier enumeration value.
        """
        if score >= Decimal(str(self._settings.sr117_high_risk_threshold)):
            return ModelRiskTier.CRITICAL if score >= Decimal("0.85") else ModelRiskTier.HIGH
        if score >= Decimal("0.40"):
            return ModelRiskTier.MEDIUM
        return ModelRiskTier.LOW

    def _compute_next_review_date(self, risk_tier: ModelRiskTier) -> datetime:
        """Determine next review date based on risk tier.

        Critical/High models: annual review (365 days).
        Medium models: biennial review (730 days).
        Low models: triennial review (1095 days).

        Args:
            risk_tier: SR 11-7 risk tier.

        Returns:
            Next review date as UTC datetime.
        """
        now = datetime.now(timezone.utc)
        if risk_tier in (ModelRiskTier.CRITICAL, ModelRiskTier.HIGH):
            return now + timedelta(days=365)
        if risk_tier == ModelRiskTier.MEDIUM:
            return now + timedelta(days=730)
        return now + timedelta(days=1095)

    def _generate_findings(self, request: ModelRiskAssessmentRequest, score: Decimal) -> list[str]:
        """Generate SR 11-7 assessment findings.

        Args:
            request: Assessment request with model details.
            score: Computed risk score.

        Returns:
            List of finding strings for the assessment report.
        """
        findings: list[str] = []
        if request.regulatory_capital_impact:
            findings.append(
                "Model influences regulatory capital calculations — heightened SR 11-7 scrutiny required."
            )
        if request.customer_facing:
            findings.append(
                "Model output is customer-facing — adverse action notice requirements may apply (ECOA/Regulation B)."
            )
        if len(request.known_limitations) > 3:
            findings.append(
                f"Model has {len(request.known_limitations)} known limitations — "
                "comprehensive compensating controls and enhanced monitoring required."
            )
        if score >= Decimal("0.7"):
            findings.append(
                "High composite risk score — independent model validation by a party separate "
                "from model development is mandatory per SR 11-7."
            )
        if not request.compensating_controls:
            findings.append(
                "No compensating controls documented — model risk policy requires at least "
                "one documented control for all production models."
            )
        return findings

    async def assess_model(
        self,
        request: ModelRiskAssessmentRequest,
        tenant_id: uuid.UUID,
    ) -> ModelRiskAssessmentResponse:
        """Perform an SR 11-7 model risk assessment.

        Computes risk score, assigns tier, generates findings, determines
        independent validation requirement, and persists the assessment.

        Args:
            request: Model risk assessment parameters.
            tenant_id: Tenant submitting the assessment.

        Returns:
            ModelRiskAssessmentResponse with risk tier and recommended actions.
        """
        logger.info(
            "Performing SR 11-7 model risk assessment",
            tenant_id=str(tenant_id),
            model_name=request.model_name,
            model_type=request.model_type,
        )

        risk_score = self._compute_risk_score(request)
        risk_tier = self._tier_from_score(risk_score)
        next_review_date = self._compute_next_review_date(risk_tier)
        findings = self._generate_findings(request, risk_score)

        independent_validation_required = (
            self._settings.sr117_validation_required
            or risk_tier in (ModelRiskTier.HIGH, ModelRiskTier.CRITICAL)
        )

        recommended_actions: list[str] = []
        if independent_validation_required:
            recommended_actions.append(
                "Engage independent model validation team — separate from model development."
            )
        recommended_actions.append(
            "Document model limitations and monitoring thresholds in the model risk inventory."
        )
        if risk_tier == ModelRiskTier.CRITICAL:
            recommended_actions.append(
                "Obtain MRC (Model Risk Committee) approval before production deployment."
            )

        assessment = ModelRiskAssessment(
            tenant_id=tenant_id,
            model_name=request.model_name,
            model_version=request.model_version,
            model_purpose=request.model_purpose,
            model_type=request.model_type,
            business_line=request.business_line,
            estimated_annual_exposure=request.estimated_annual_exposure,
            regulatory_capital_impact=request.regulatory_capital_impact,
            customer_facing=request.customer_facing,
            risk_tier=risk_tier.value,
            risk_score=risk_score,
            validation_status=ModelRiskStatus.PENDING.value,
            independent_validation_required=independent_validation_required,
            findings=findings,
            recommended_actions=recommended_actions,
            next_review_date=next_review_date.isoformat(),
            training_data_description=request.training_data_description,
            validation_data_description=request.validation_data_description,
            known_limitations=request.known_limitations,
            compensating_controls=request.compensating_controls,
            assessment_metadata=request.metadata,
        )

        created = await self._repo.create(assessment)

        await self._publisher.publish(
            "finserv.model_risk.assessment.created",
            {
                "tenant_id": str(tenant_id),
                "assessment_id": str(created.id),
                "model_name": request.model_name,
                "risk_tier": risk_tier.value,
                "risk_score": float(risk_score),
                "independent_validation_required": independent_validation_required,
            },
        )

        logger.info(
            "SR 11-7 model risk assessment complete",
            assessment_id=str(created.id),
            risk_tier=risk_tier.value,
            risk_score=float(risk_score),
        )
        return ModelRiskAssessmentResponse.model_validate(created)

    async def get_assessment(
        self,
        assessment_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> ModelRiskAssessmentResponse:
        """Retrieve a model risk assessment by ID.

        Args:
            assessment_id: Assessment UUID.
            tenant_id: Tenant requesting the assessment.

        Returns:
            ModelRiskAssessmentResponse.

        Raises:
            NotFoundError: If assessment does not exist for this tenant.
        """
        assessment = await self._repo.get_by_id(assessment_id, tenant_id)
        if assessment is None:
            raise NotFoundError(
                resource="ModelRiskAssessment",
                resource_id=str(assessment_id),
            )
        return ModelRiskAssessmentResponse.model_validate(assessment)


class PCIDSSService:
    """Performs PCI DSS v4.0 control compliance scans.

    Evaluates cardholder data environment (CDE) controls across all
    12 PCI DSS requirement areas, producing evidence suitable for
    Qualified Security Assessor (QSA) review.
    """

    # PCI DSS v4.0 control catalogue (representative subset)
    _CONTROL_CATALOGUE: list[dict[str, Any]] = [
        {
            "requirement": "1",
            "control_id": "1.1",
            "description": "Network security controls are established and implemented",
        },
        {
            "requirement": "1",
            "control_id": "1.2",
            "description": "Network security controls are configured and maintained",
        },
        {
            "requirement": "2",
            "control_id": "2.1",
            "description": "System components are securely configured and managed",
        },
        {
            "requirement": "3",
            "control_id": "3.1",
            "description": "Cardholder data storage policies are defined",
        },
        {
            "requirement": "3",
            "control_id": "3.4",
            "description": "Primary account numbers (PAN) are rendered unreadable anywhere they are stored",
        },
        {
            "requirement": "4",
            "control_id": "4.1",
            "description": "Strong cryptography is used to safeguard PAN during transmission over open public networks",
        },
        {
            "requirement": "5",
            "control_id": "5.1",
            "description": "Anti-malware solutions are deployed and maintained",
        },
        {
            "requirement": "6",
            "control_id": "6.1",
            "description": "Secure development processes are defined and followed",
        },
        {
            "requirement": "7",
            "control_id": "7.1",
            "description": "Access to system components and cardholder data is limited to only those individuals whose job requires such access",
        },
        {
            "requirement": "8",
            "control_id": "8.1",
            "description": "User identification and authentication policies and procedures are defined and implemented",
        },
        {
            "requirement": "9",
            "control_id": "9.1",
            "description": "Physical access controls are implemented",
        },
        {
            "requirement": "10",
            "control_id": "10.1",
            "description": "Audit logs are implemented to support the detection of anomalies and suspicious activity",
        },
        {
            "requirement": "11",
            "control_id": "11.1",
            "description": "Security vulnerabilities are identified and managed",
        },
        {
            "requirement": "12",
            "control_id": "12.1",
            "description": "Information security policy is defined and known to all affected parties",
        },
    ]

    def __init__(
        self,
        pci_repository: PCIDSSRepository,
        event_publisher: EventPublisher,
        settings: Settings,
    ) -> None:
        """Initialize PCI DSS service.

        Args:
            pci_repository: Repository for PCI control persistence.
            event_publisher: Kafka event publisher.
            settings: Service settings.
        """
        self._repo = pci_repository
        self._publisher = event_publisher
        self._settings = settings

    def _evaluate_control(
        self,
        control: dict[str, Any],
        request: PCIDSSScanRequest,
    ) -> PCIControlResult:
        """Evaluate a single PCI DSS control against the scan scope.

        For each control in the catalogue, this performs a deterministic
        evaluation based on request flags (encryption, access controls, etc.).
        In production, each control would invoke a real scanner or query
        infrastructure state.

        Args:
            control: Control catalogue entry.
            request: Scan request with scope flags.

        Returns:
            PCIControlResult with evaluated status.
        """
        from aumos_finserv_overlay.api.schemas import PCIDSSRequirement, PCIControlStatus

        requirement = control["requirement"]
        status = PCIControlStatus.COMPLIANT
        evidence = f"Automated evaluation of control {control['control_id']} — scope: {request.scope_description}"
        remediation_guidance: str | None = None
        risk_level = "low"

        # Apply evaluation logic based on scan flags
        if requirement == "3" and not request.scan_encryption:
            status = PCIControlStatus.NOT_APPLICABLE
        elif requirement == "4" and not request.scan_encryption:
            status = PCIControlStatus.NOT_APPLICABLE
        elif requirement in ("7", "8") and not request.scan_access_controls:
            status = PCIControlStatus.NOT_APPLICABLE
        elif requirement == "1" and not request.scan_network_segmentation:
            status = PCIControlStatus.NOT_APPLICABLE

        return PCIControlResult(
            requirement=PCIDSSRequirement(requirement),
            control_id=control["control_id"],
            control_description=control["description"],
            status=status,
            evidence=evidence,
            remediation_guidance=remediation_guidance,
            risk_level=risk_level,
        )

    async def scan(
        self,
        request: PCIDSSScanRequest,
        tenant_id: uuid.UUID,
    ) -> PCIDSSScanResponse:
        """Perform a PCI DSS v4.0 control scan.

        Evaluates applicable controls from the catalogue, persists results,
        and publishes a compliance event. Returns scan results suitable for
        QSA-reviewed evidence packages.

        Args:
            request: Scan parameters including scope and requirement filters.
            tenant_id: Tenant requesting the scan.

        Returns:
            PCIDSSScanResponse with all control results and aggregated metrics.
        """
        logger.info(
            "Starting PCI DSS control scan",
            tenant_id=str(tenant_id),
            scope=request.scope_description,
            pci_version=self._settings.pci_dss_version,
        )

        scan_id = uuid.uuid4()
        scan_started_at = datetime.now(timezone.utc)

        # Filter catalogue by requested requirements
        catalogue = self._CONTROL_CATALOGUE
        if request.requirements_to_scan:
            required_values = {r.value for r in request.requirements_to_scan}
            catalogue = [c for c in catalogue if c["requirement"] in required_values]

        # Evaluate each control
        control_results = [self._evaluate_control(c, request) for c in catalogue]

        # Persist control records
        from aumos_finserv_overlay.api.schemas import PCIControlStatus

        control_models = []
        for result in control_results:
            control_models.append(
                PCIDSSControl(
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    requirement=result.requirement.value,
                    control_id=result.control_id,
                    control_description=result.control_description,
                    status=result.status.value,
                    evidence=result.evidence,
                    remediation_guidance=result.remediation_guidance,
                    risk_level=result.risk_level,
                    scope_description=request.scope_description,
                    pci_dss_version=self._settings.pci_dss_version,
                )
            )

        await self._repo.create_batch(scan_id=scan_id, tenant_id=tenant_id, controls=control_models)

        scan_completed_at = datetime.now(timezone.utc)

        compliant = sum(1 for r in control_results if r.status == PCIControlStatus.COMPLIANT)
        non_compliant = sum(1 for r in control_results if r.status == PCIControlStatus.NON_COMPLIANT)
        compensating = sum(1 for r in control_results if r.status == PCIControlStatus.COMPENSATING_CONTROL)
        total_applicable = sum(
            1 for r in control_results if r.status != PCIControlStatus.NOT_APPLICABLE
        )
        compliance_pct = (compliant / total_applicable * 100) if total_applicable > 0 else 100.0
        qsa_ready = non_compliant == 0

        await self._publisher.publish(
            "finserv.pci_dss.scan.completed",
            {
                "tenant_id": str(tenant_id),
                "scan_id": str(scan_id),
                "total_controls": len(control_results),
                "compliant": compliant,
                "non_compliant": non_compliant,
                "compliance_percentage": compliance_pct,
                "qsa_ready": qsa_ready,
            },
        )

        logger.info(
            "PCI DSS scan complete",
            scan_id=str(scan_id),
            total=len(control_results),
            compliant=compliant,
            non_compliant=non_compliant,
            qsa_ready=qsa_ready,
        )

        return PCIDSSScanResponse(
            id=scan_id,
            tenant_id=tenant_id,
            scope_description=request.scope_description,
            pci_dss_version=self._settings.pci_dss_version,
            scan_started_at=scan_started_at,
            scan_completed_at=scan_completed_at,
            total_controls=len(control_results),
            compliant_controls=compliant,
            non_compliant_controls=non_compliant,
            compensating_controls=compensating,
            compliance_percentage=round(compliance_pct, 2),
            control_results=control_results,
            qsa_ready=qsa_ready,
        )


class DORAService:
    """Evaluates DORA (Digital Operational Resilience Act) compliance status.

    Implements EU Regulation 2022/2554 Article requirements including ICT
    risk management, incident reporting, resilience testing, third-party
    ICT oversight, and information sharing.
    """

    def __init__(
        self,
        dora_repository: DORARepository,
        event_publisher: EventPublisher,
        settings: Settings,
    ) -> None:
        """Initialize DORA service.

        Args:
            dora_repository: Repository for DORA assessment persistence.
            event_publisher: Kafka event publisher.
            settings: Service settings with DORA thresholds.
        """
        self._repo = dora_repository
        self._publisher = event_publisher
        self._settings = settings

    async def get_status(self, tenant_id: uuid.UUID) -> DORAStatusResponse:
        """Retrieve the most recent DORA resilience status for a tenant.

        Creates an initial 'under_review' assessment if none exists.

        Args:
            tenant_id: Tenant requesting DORA status.

        Returns:
            DORAStatusResponse with current resilience posture.
        """
        assessment = await self._repo.get_latest_by_tenant(tenant_id)

        if assessment is None:
            # Bootstrap an initial assessment record
            assessment = await self._repo.create(
                DORAAssessment(
                    tenant_id=tenant_id,
                    overall_status="under_review",
                    ict_register_complete=False,
                    testing_program_active=False,
                    incident_reporting_configured=False,
                    third_party_oversight_active=False,
                    information_sharing_active=False,
                    rto_meets_threshold=False,
                    rpo_meets_threshold=False,
                    current_rto_hours=None,
                    current_rpo_hours=None,
                    open_gaps=[
                        "ICT third-party register not yet completed",
                        "DORA testing programme not yet configured",
                        "ICT incident reporting not yet configured",
                    ],
                    next_assessment_date=(
                        datetime.now(timezone.utc) + timedelta(days=90)
                    ).isoformat(),
                )
            )

        rto_ok = (
            assessment.current_rto_hours is not None
            and float(assessment.current_rto_hours) <= self._settings.dora_rto_threshold_hours
        )
        rpo_ok = (
            assessment.current_rpo_hours is not None
            and float(assessment.current_rpo_hours) <= self._settings.dora_rpo_threshold_hours
        )

        return DORAStatusResponse(
            id=assessment.id,
            tenant_id=tenant_id,
            assessment_date=assessment.created_at,
            overall_status=DORAResilienceStatus(assessment.overall_status),
            ict_register_complete=assessment.ict_register_complete,
            testing_program_active=assessment.testing_program_active,
            incident_reporting_configured=assessment.incident_reporting_configured,
            third_party_oversight_active=assessment.third_party_oversight_active,
            information_sharing_active=assessment.information_sharing_active,
            rto_meets_threshold=rto_ok,
            rpo_meets_threshold=rpo_ok,
            current_rto_hours=(
                float(assessment.current_rto_hours) if assessment.current_rto_hours is not None else None
            ),
            current_rpo_hours=(
                float(assessment.current_rpo_hours) if assessment.current_rpo_hours is not None else None
            ),
            open_gaps=assessment.open_gaps or [],
            next_assessment_date=datetime.fromisoformat(assessment.next_assessment_date),
            created_at=assessment.created_at,
        )


class SyntheticTransactionService:
    """Generates synthetic financial transaction datasets.

    Produces statistically realistic transaction data with configurable
    fraud injection rates, transaction types, and demographic distributions.
    All PII fields are masked by default, making datasets safe for
    ML model training and stress-testing fraud detection pipelines.
    """

    def __init__(
        self,
        transaction_repository: SyntheticTransactionRepository,
        transaction_generator: TransactionGenerator,
        event_publisher: EventPublisher,
        settings: Settings,
    ) -> None:
        """Initialize synthetic transaction service.

        Args:
            transaction_repository: Repository for transaction job persistence.
            transaction_generator: Transaction generation adapter.
            event_publisher: Kafka event publisher.
            settings: Service settings.
        """
        self._repo = transaction_repository
        self._generator = transaction_generator
        self._publisher = event_publisher
        self._settings = settings

    async def generate(
        self,
        request: SyntheticTransactionRequest,
        tenant_id: uuid.UUID,
    ) -> SyntheticTransactionResponse:
        """Generate a synthetic financial transaction dataset.

        Creates a job record, runs the generator, uploads output to storage,
        and publishes a completion event.

        Args:
            request: Transaction generation parameters.
            tenant_id: Tenant submitting the request.

        Returns:
            SyntheticTransactionResponse with job ID and output URI.

        Raises:
            ValidationError: If num_transactions exceeds tenant limit.
        """
        if request.num_transactions > self._settings.synth_max_transactions_per_request:
            raise ValidationError(
                message=(
                    f"num_transactions {request.num_transactions} exceeds maximum "
                    f"{self._settings.synth_max_transactions_per_request}"
                ),
            )

        logger.info(
            "Generating synthetic transactions",
            tenant_id=str(tenant_id),
            num_transactions=request.num_transactions,
            fraud_rate=request.fraud_rate,
        )

        job = SyntheticTransaction(
            tenant_id=tenant_id,
            num_transactions=request.num_transactions,
            transaction_types=[t.value for t in request.transaction_types],
            fraud_rate=Decimal(str(request.fraud_rate)),
            currency=request.currency,
            amount_min=request.amount_min,
            amount_max=request.amount_max,
            status="running",
            generation_metadata=request.metadata,
        )
        created_job = await self._repo.create(job)

        try:
            output_bytes, fraud_count, legitimate_count = await self._generator.generate(request)

            output_key = f"tenants/{tenant_id}/synth-transactions/{created_job.id}.csv"
            output_uri = f"s3://{self._settings.synth_output_bucket}/{output_key}"

            await self._repo.update_completion(
                job_id=created_job.id,
                output_uri=output_uri,
                fraud_count=fraud_count,
                legitimate_count=legitimate_count,
            )

            await self._publisher.publish(
                "finserv.synth_transactions.generated",
                {
                    "tenant_id": str(tenant_id),
                    "job_id": str(created_job.id),
                    "num_transactions": request.num_transactions,
                    "fraud_count": fraud_count,
                    "output_uri": output_uri,
                },
            )

            logger.info(
                "Synthetic transactions generated",
                job_id=str(created_job.id),
                fraud_count=fraud_count,
                legitimate_count=legitimate_count,
            )

            return SyntheticTransactionResponse(
                id=created_job.id,
                tenant_id=tenant_id,
                num_transactions=request.num_transactions,
                transaction_types=request.transaction_types,
                fraud_rate=request.fraud_rate,
                currency=request.currency,
                status="completed",
                output_uri=output_uri,
                fraud_count=fraud_count,
                legitimate_count=legitimate_count,
                created_at=created_job.created_at,
                completed_at=datetime.now(timezone.utc),
            )

        except Exception as exc:
            await self._repo.update_failure(job_id=created_job.id, error_message=str(exc))
            logger.error(
                "Synthetic transaction generation failed",
                job_id=str(created_job.id),
                error=str(exc),
            )
            raise


class RegulatoryReportService:
    """Generates regulatory reports for SEC, CFPB, FINRA, OCC, FDIC, and FRB.

    Produces regulator-specific report documents (PDF, XBRL, JSON) incorporating
    SEC AI disclosure sections, SOX attestation references, and SR 11-7 model
    inventory summaries.
    """

    def __init__(
        self,
        report_repository: RegulatoryReportRepository,
        model_risk_repository: ModelRiskRepository,
        sox_repository: SOXEvidenceRepository,
        report_generator: ReportGenerator,
        event_publisher: EventPublisher,
        settings: Settings,
    ) -> None:
        """Initialize regulatory report service.

        Args:
            report_repository: Repository for report record persistence.
            model_risk_repository: Repository for reading model assessments.
            sox_repository: Repository for reading SOX evidence.
            report_generator: Report document generation adapter.
            event_publisher: Kafka event publisher.
            settings: Service settings.
        """
        self._report_repo = report_repository
        self._model_repo = model_risk_repository
        self._sox_repo = sox_repository
        self._generator = report_generator
        self._publisher = event_publisher
        self._settings = settings

    async def list_reports(
        self,
        tenant_id: uuid.UUID,
        regulator: str | None,
        page_request: PageRequest,
    ) -> RegulatoryReportListResponse:
        """List regulatory reports for a tenant.

        Args:
            tenant_id: Tenant requesting the list.
            regulator: Optional regulator filter.
            page_request: Pagination parameters.

        Returns:
            RegulatoryReportListResponse with paginated report list.
        """
        reports, total = await self._report_repo.list_by_tenant(
            tenant_id=tenant_id,
            regulator=regulator,
            page=page_request.page,
            page_size=page_request.page_size,
        )
        return RegulatoryReportListResponse(
            items=[RegulatoryReportResponse.model_validate(r) for r in reports],
            total=total,
            page=page_request.page,
            page_size=page_request.page_size,
        )

    async def generate_report(
        self,
        request: RegulatoryReportRequest,
        tenant_id: uuid.UUID,
    ) -> RegulatoryReportResponse:
        """Generate a regulatory report document.

        Collects referenced model assessments and SOX evidence, renders
        the report document via the generator adapter, and persists
        the result.

        Args:
            request: Report generation parameters.
            tenant_id: Tenant requesting the report.

        Returns:
            RegulatoryReportResponse with output URI.

        Raises:
            ValidationError: If regulator is not supported.
        """
        if request.regulator.value not in self._settings.supported_regulators:
            raise ValidationError(
                message=f"Regulator '{request.regulator}' is not supported. "
                f"Supported: {self._settings.supported_regulators}",
            )

        logger.info(
            "Generating regulatory report",
            tenant_id=str(tenant_id),
            regulator=request.regulator.value,
            report_type=request.report_type.value,
        )

        # Collect referenced data
        model_assessments: list[dict[str, Any]] = []
        for assessment_id in request.model_inventory_ids:
            assessment = await self._model_repo.get_by_id(assessment_id, tenant_id)
            if assessment is not None:
                model_assessments.append(
                    {
                        "model_name": assessment.model_name,
                        "risk_tier": assessment.risk_tier,
                        "validation_status": assessment.validation_status,
                    }
                )

        sox_evidence_items: list[dict[str, Any]] = []
        for evidence_id in request.sox_evidence_ids:
            evidence = await self._sox_repo.get_by_id(evidence_id, tenant_id)
            if evidence is not None:
                sox_evidence_items.append(
                    {
                        "control_id": evidence.control_id,
                        "control_area": evidence.control_area,
                        "status": evidence.status,
                    }
                )

        # Create report record
        report = RegulatoryReport(
            tenant_id=tenant_id,
            regulator=request.regulator.value,
            report_type=request.report_type.value,
            reporting_period_start=request.reporting_period_start.isoformat(),
            reporting_period_end=request.reporting_period_end.isoformat(),
            entity_name=request.entity_name,
            status="generating",
            report_metadata=request.metadata,
        )
        created_report = await self._report_repo.create(report)

        try:
            document_bytes, report_format, page_count = await self._generator.generate_report(
                request=request,
                tenant_id=tenant_id,
                model_assessments=model_assessments,
                sox_evidence_items=sox_evidence_items,
            )

            output_key = (
                f"tenants/{tenant_id}/reports/{created_report.id}"
                f".{report_format.lower()}"
            )
            output_uri = f"s3://{self._settings.report_output_bucket}/{output_key}"

            await self._report_repo.update_completion(
                report_id=created_report.id,
                output_uri=output_uri,
                page_count=page_count,
                report_format=report_format,
            )

            await self._publisher.publish(
                "finserv.regulatory_report.generated",
                {
                    "tenant_id": str(tenant_id),
                    "report_id": str(created_report.id),
                    "regulator": request.regulator.value,
                    "report_type": request.report_type.value,
                    "output_uri": output_uri,
                },
            )

            logger.info(
                "Regulatory report generated",
                report_id=str(created_report.id),
                regulator=request.regulator.value,
                format=report_format,
                pages=page_count,
            )

            return RegulatoryReportResponse(
                id=created_report.id,
                tenant_id=tenant_id,
                regulator=request.regulator,
                report_type=request.report_type,
                reporting_period_start=request.reporting_period_start,
                reporting_period_end=request.reporting_period_end,
                entity_name=request.entity_name,
                status="completed",
                output_uri=output_uri,
                report_format=report_format,
                page_count=page_count,
                created_at=created_report.created_at,
                completed_at=datetime.now(timezone.utc),
            )

        except Exception as exc:
            logger.error(
                "Regulatory report generation failed",
                report_id=str(created_report.id),
                error=str(exc),
            )
            raise
