"""SQLAlchemy ORM models for aumos-finserv-overlay.

All models use the `fsv_` table prefix and extend AumOSModel for
standard tenant isolation, timestamps, and UUID primary keys.
"""

import uuid
from decimal import Decimal

from sqlalchemy import Boolean, ForeignKey, Integer, Numeric, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aumos_common.database import AumOSModel


class SOXEvidence(AumOSModel):
    """SOX compliance evidence record.

    Stores collected evidence for Sarbanes-Oxley internal control assessments.
    Evidence is immutably archived for a minimum of 7 years per PCAOB requirements.

    Attributes:
        control_id: Control identifier (e.g. ITGC-001).
        control_area: COSO control area classification.
        control_description: Human-readable control description.
        evidence_description: Description of evidence collected.
        evidence_artifacts: List of artifact URIs.
        control_owner: Name or ID of the control owner.
        review_period_start: Start of review period (ISO 8601).
        review_period_end: End of review period (ISO 8601).
        is_key_control: Whether this is a key SOX control.
        status: Evidence review status.
        metadata: Additional evidence metadata as JSONB.
    """

    __tablename__ = "fsv_sox_evidence"

    control_id: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        comment="Control identifier e.g. ITGC-001",
    )
    control_area: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="COSO control area: ITGC | APPLICATION | FINANCIAL_REPORTING | ENTITY_LEVEL | DISCLOSURE",
    )
    control_description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    evidence_description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    evidence_artifacts: Mapped[list] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        comment="List of artifact storage URIs",
    )
    control_owner: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    review_period_start: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="ISO 8601 start of review period",
    )
    review_period_end: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="ISO 8601 end of review period",
    )
    is_key_control: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="pending_review",
        comment="collected | pending_review | approved | remediation_required | deficiency",
    )
    sox_metadata: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        name="metadata",
    )


class ModelRiskAssessment(AumOSModel):
    """SR 11-7 model risk assessment record.

    Implements the Federal Reserve / OCC SR 11-7 guidance on model risk
    management. Covers model identification, risk tiering, independent
    validation status, and remediation tracking.

    Attributes:
        model_name: Name/identifier of the model.
        model_version: Model version string.
        model_purpose: Business purpose and use case.
        model_type: Type classification (credit_scoring, fraud_detection, etc.).
        business_line: Business line owning the model.
        estimated_annual_exposure: Estimated annual financial exposure (USD).
        regulatory_capital_impact: Whether model influences regulatory capital.
        customer_facing: Whether model decisions are customer-facing.
        risk_tier: SR 11-7 risk tier (low | medium | high | critical).
        risk_score: Composite risk score (0.0–1.0).
        validation_status: Independent validation status.
        independent_validation_required: Whether independent validation is needed.
        findings: List of assessment findings.
        recommended_actions: List of recommended mitigations.
        next_review_date: Date of next scheduled review.
        assessment_metadata: Additional metadata as JSONB.
    """

    __tablename__ = "fsv_model_risk_assessments"

    model_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    model_version: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    model_purpose: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    model_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="credit_scoring | fraud_detection | pricing | capital_modeling | etc.",
    )
    business_line: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    estimated_annual_exposure: Mapped[Decimal] = mapped_column(
        Numeric(precision=18, scale=2),
        nullable=False,
        comment="Estimated annual financial exposure influenced by model (USD)",
    )
    regulatory_capital_impact: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
    customer_facing: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
    risk_tier: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="medium",
        comment="low | medium | high | critical",
    )
    risk_score: Mapped[Decimal] = mapped_column(
        Numeric(precision=5, scale=4),
        nullable=False,
        default=Decimal("0.0"),
        comment="Composite risk score 0.0–1.0",
    )
    validation_status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="pending",
        comment="pending | in_validation | approved | conditionally_approved | rejected | requires_remediation",
    )
    independent_validation_required: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )
    findings: Mapped[list] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        comment="List of assessment finding strings",
    )
    recommended_actions: Mapped[list] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    next_review_date: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="ISO 8601 next review date",
    )
    training_data_description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="",
    )
    validation_data_description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="",
    )
    known_limitations: Mapped[list] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    compensating_controls: Mapped[list] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    assessment_metadata: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        name="metadata",
    )


class PCIDSSControl(AumOSModel):
    """PCI DSS control compliance record.

    Tracks compliance status of individual PCI DSS v4.0 controls
    within the cardholder data environment (CDE).

    Attributes:
        scan_id: UUID grouping all controls from one scan session.
        requirement: PCI DSS requirement number (1–12).
        control_id: Specific control identifier within the requirement.
        control_description: Description of the control.
        status: Compliance status of the control.
        evidence: Evidence supporting the status determination.
        remediation_guidance: Guidance if non-compliant.
        risk_level: Assessed risk level if non-compliant.
        scope_description: CDE scope description for this assessment.
    """

    __tablename__ = "fsv_pci_controls"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment="Groups all controls from one PCI scan session",
    )
    requirement: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        comment="PCI DSS requirement number 1-12",
    )
    control_id: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    control_description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="not_applicable",
        comment="compliant | non_compliant | not_applicable | compensating_control | in_remediation",
    )
    evidence: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="",
    )
    remediation_guidance: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    risk_level: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="low",
        comment="low | medium | high | critical",
    )
    scope_description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="",
    )
    pci_dss_version: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        default="4.0",
    )


class DORAAssessment(AumOSModel):
    """DORA ICT operational resilience assessment record.

    Tracks Digital Operational Resilience Act (EU 2022/2554) compliance
    status for ICT systems, third-party providers, and resilience testing.

    Attributes:
        overall_status: Overall DORA resilience assessment outcome.
        ict_register_complete: Whether ICT third-party register is complete.
        testing_program_active: Whether DORA-compliant testing programme is active.
        incident_reporting_configured: Whether ICT incident reporting is configured.
        third_party_oversight_active: Whether third-party ICT oversight is active.
        information_sharing_active: Whether information sharing is configured.
        current_rto_hours: Current RTO for critical systems (hours).
        current_rpo_hours: Current RPO for critical systems (hours).
        open_gaps: List of identified compliance gaps.
        next_assessment_date: Next scheduled DORA assessment date.
        assessment_metadata: Additional assessment data as JSONB.
    """

    __tablename__ = "fsv_dora_assessments"

    overall_status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="under_review",
        comment="fully_compliant | partially_compliant | non_compliant | under_review",
    )
    ict_register_complete: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    testing_program_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    incident_reporting_configured: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    third_party_oversight_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    information_sharing_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    rto_meets_threshold: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    rpo_meets_threshold: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    current_rto_hours: Mapped[float | None] = mapped_column(
        Numeric(precision=6, scale=2),
        nullable=True,
        comment="Current measured RTO for critical ICT systems (hours)",
    )
    current_rpo_hours: Mapped[float | None] = mapped_column(
        Numeric(precision=6, scale=2),
        nullable=True,
        comment="Current measured RPO for critical ICT systems (hours)",
    )
    open_gaps: Mapped[list] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        comment="List of identified DORA compliance gaps",
    )
    next_assessment_date: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="ISO 8601 next assessment date",
    )
    assessment_metadata: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        name="metadata",
    )


class SyntheticTransaction(AumOSModel):
    """Synthetic financial transaction record.

    Stores metadata for generated synthetic transaction datasets.
    Individual transaction rows are stored in object storage for
    performance; this model tracks the generation job metadata.

    Attributes:
        num_transactions: Number of transactions requested.
        transaction_types: List of transaction types included.
        fraud_rate: Fraction of transactions labelled fraudulent.
        currency: ISO 4217 currency code.
        amount_min: Minimum transaction amount.
        amount_max: Maximum transaction amount.
        status: Generation job status.
        output_uri: Storage URI for generated dataset.
        fraud_count: Actual number of fraudulent transactions.
        legitimate_count: Actual number of legitimate transactions.
        generation_metadata: Additional generation parameters.
    """

    __tablename__ = "fsv_synthetic_transactions"

    num_transactions: Mapped[int] = mapped_column(Integer, nullable=False)
    transaction_types: Mapped[list] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    fraud_rate: Mapped[Decimal] = mapped_column(
        Numeric(precision=5, scale=4),
        nullable=False,
        default=Decimal("0.02"),
    )
    currency: Mapped[str] = mapped_column(String(3), nullable=False, default="USD")
    amount_min: Mapped[Decimal] = mapped_column(
        Numeric(precision=18, scale=2),
        nullable=False,
        default=Decimal("0.01"),
    )
    amount_max: Mapped[Decimal] = mapped_column(
        Numeric(precision=18, scale=2),
        nullable=False,
        default=Decimal("1000000.00"),
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="pending",
        comment="pending | running | completed | failed",
    )
    output_uri: Mapped[str | None] = mapped_column(Text, nullable=True)
    fraud_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    legitimate_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    generation_metadata: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        name="metadata",
    )


class RegulatoryReport(AumOSModel):
    """Regulatory report record.

    Tracks generated regulatory reports for SEC, CFPB, FINRA, OCC, FDIC,
    and FRB. Report documents are stored in object storage.

    Attributes:
        regulator: Target regulatory body.
        report_type: Type of regulatory report.
        reporting_period_start: Start of reporting period.
        reporting_period_end: End of reporting period.
        entity_name: Legal entity name in the report.
        status: Report generation status.
        output_uri: Storage URI for generated report.
        report_format: Output format (PDF | XBRL | JSON).
        page_count: Number of pages in generated report.
        report_metadata: Additional report parameters.
    """

    __tablename__ = "fsv_regulatory_reports"

    regulator: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
        comment="SEC | CFPB | FINRA | OCC | FDIC | FRB",
    )
    report_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="Form 10-K | Form 10-Q | SAR | CTR | FINRA FOCUS | Call Report | etc.",
    )
    reporting_period_start: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    reporting_period_end: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    entity_name: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="pending",
        comment="pending | generating | completed | failed",
    )
    output_uri: Mapped[str | None] = mapped_column(Text, nullable=True)
    report_format: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        default="PDF",
    )
    page_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    report_metadata: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        name="metadata",
    )
