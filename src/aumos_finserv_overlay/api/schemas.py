"""Pydantic request/response schemas for aumos-finserv-overlay.

All schemas use strict validation via Pydantic v2. Request schemas validate
at the API boundary; response schemas control serialisation.
"""

import uuid
from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ============================================================================
# Enums
# ============================================================================


class SOXControlArea(str, Enum):
    """SOX internal control areas per COSO framework."""

    ITGC = "ITGC"  # IT General Controls
    APPLICATION = "APPLICATION"
    FINANCIAL_REPORTING = "FINANCIAL_REPORTING"
    ENTITY_LEVEL = "ENTITY_LEVEL"
    DISCLOSURE = "DISCLOSURE"


class SOXEvidenceStatus(str, Enum):
    """SOX evidence collection status."""

    COLLECTED = "collected"
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    REMEDIATION_REQUIRED = "remediation_required"
    DEFICIENCY = "deficiency"


class ModelRiskTier(str, Enum):
    """SR 11-7 model risk tier classification."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ModelRiskStatus(str, Enum):
    """SR 11-7 model validation status."""

    PENDING = "pending"
    IN_VALIDATION = "in_validation"
    APPROVED = "approved"
    CONDITIONALLY_APPROVED = "conditionally_approved"
    REJECTED = "rejected"
    REQUIRES_REMEDIATION = "requires_remediation"


class PCIDSSRequirement(str, Enum):
    """PCI DSS v4.0 requirement areas."""

    NETWORK_SECURITY = "1"
    SECURE_CONFIGURATIONS = "2"
    CARDHOLDER_DATA = "3"
    ENCRYPTION_IN_TRANSIT = "4"
    VULNERABILITY_MANAGEMENT = "5"
    SECURE_DEVELOPMENT = "6"
    RESTRICT_ACCESS = "7"
    AUTHENTICATION = "8"
    PHYSICAL_SECURITY = "9"
    LOGGING_MONITORING = "10"
    TESTING = "11"
    INFORMATION_SECURITY = "12"


class PCIControlStatus(str, Enum):
    """PCI DSS control compliance status."""

    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"
    COMPENSATING_CONTROL = "compensating_control"
    IN_REMEDIATION = "in_remediation"


class DORAResilienceStatus(str, Enum):
    """DORA ICT resilience assessment outcome."""

    FULLY_COMPLIANT = "fully_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NON_COMPLIANT = "non_compliant"
    UNDER_REVIEW = "under_review"


class TransactionType(str, Enum):
    """Synthetic financial transaction types."""

    PAYMENT = "payment"
    TRANSFER = "transfer"
    WITHDRAWAL = "withdrawal"
    DEPOSIT = "deposit"
    TRADE = "trade"
    SETTLEMENT = "settlement"
    FX_CONVERSION = "fx_conversion"
    LOAN_DISBURSEMENT = "loan_disbursement"
    LOAN_REPAYMENT = "loan_repayment"


class RegulatoryBody(str, Enum):
    """Supported regulatory bodies for report generation."""

    SEC = "SEC"
    CFPB = "CFPB"
    FINRA = "FINRA"
    OCC = "OCC"
    FDIC = "FDIC"
    FRB = "FRB"


class ReportType(str, Enum):
    """Regulatory report types."""

    FORM_10K = "Form 10-K"
    FORM_10Q = "Form 10-Q"
    SAR = "SAR"
    CTR = "CTR"
    FINRA_FOCUS = "FINRA FOCUS"
    CALL_REPORT = "Call Report"
    DORA_INCIDENT = "DORA Incident"
    MODEL_RISK_SUMMARY = "Model Risk Summary"
    SOX_ATTESTATION = "SOX Attestation"


# ============================================================================
# SOX schemas
# ============================================================================


class SOXEvidenceRequest(BaseModel):
    """Request to collect SOX compliance evidence."""

    control_id: str = Field(description="Control identifier (e.g. ITGC-001)")
    control_area: SOXControlArea = Field(description="COSO control area")
    control_description: str = Field(description="Human-readable control description")
    evidence_description: str = Field(description="Description of evidence collected")
    evidence_artifacts: list[str] = Field(
        default_factory=list,
        description="List of artifact URIs (screenshots, logs, exports)",
    )
    control_owner: str = Field(description="Name/ID of the control owner")
    review_period_start: datetime = Field(description="Start of review period")
    review_period_end: datetime = Field(description="End of review period")
    is_key_control: bool = Field(default=False, description="Whether this is a key SOX control")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional evidence metadata")


class SOXEvidenceResponse(BaseModel):
    """SOX evidence record response."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    control_id: str
    control_area: SOXControlArea
    control_description: str
    evidence_description: str
    evidence_artifacts: list[str]
    control_owner: str
    review_period_start: datetime
    review_period_end: datetime
    is_key_control: bool
    status: SOXEvidenceStatus
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class SOXStatusResponse(BaseModel):
    """SOX compliance status summary."""

    tenant_id: uuid.UUID
    total_controls: int
    approved_controls: int
    pending_review: int
    deficiencies: int
    material_weaknesses: int
    compliance_percentage: float = Field(description="Percentage of controls approved (0-100)")
    last_updated: datetime
    attestation_ready: bool = Field(description="Whether management attestation requirements are met")
    open_remediation_items: int


# ============================================================================
# SR 11-7 Model Risk schemas
# ============================================================================


class ModelRiskAssessmentRequest(BaseModel):
    """Request to perform an SR 11-7 model risk assessment."""

    model_name: str = Field(description="Name/identifier of the model being assessed")
    model_version: str = Field(description="Model version string")
    model_purpose: str = Field(description="Business purpose and use case")
    model_type: str = Field(description="Model type (e.g. credit_scoring, fraud_detection, pricing)")
    business_line: str = Field(description="Business line owning the model")
    estimated_annual_exposure: Decimal = Field(
        description="Estimated annual financial exposure influenced by model (USD)",
    )
    regulatory_capital_impact: bool = Field(
        default=False,
        description="Whether model influences regulatory capital calculations",
    )
    customer_facing: bool = Field(
        default=False,
        description="Whether model decisions are customer-facing",
    )
    training_data_description: str = Field(description="Description of training data sources and time range")
    validation_data_description: str = Field(description="Description of validation dataset")
    known_limitations: list[str] = Field(
        default_factory=list,
        description="Known model limitations or weaknesses",
    )
    compensating_controls: list[str] = Field(
        default_factory=list,
        description="Compensating controls mitigating model risk",
    )
    metadata: dict[str, Any] = Field(default_factory=dict)


class ModelRiskAssessmentResponse(BaseModel):
    """SR 11-7 model risk assessment result."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    model_name: str
    model_version: str
    model_purpose: str
    model_type: str
    business_line: str
    estimated_annual_exposure: Decimal
    regulatory_capital_impact: bool
    customer_facing: bool
    risk_tier: ModelRiskTier
    risk_score: Decimal = Field(description="Composite risk score 0.0–1.0")
    validation_status: ModelRiskStatus
    independent_validation_required: bool
    findings: list[str] = Field(description="Key assessment findings")
    recommended_actions: list[str] = Field(description="Recommended risk mitigations")
    next_review_date: datetime
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ============================================================================
# PCI DSS schemas
# ============================================================================


class PCIDSSScanRequest(BaseModel):
    """Request to perform a PCI DSS control scan."""

    scope_description: str = Field(description="Description of the CDE scope being scanned")
    requirements_to_scan: list[PCIDSSRequirement] = Field(
        default_factory=list,
        description="Specific PCI DSS requirements to scan (empty = all)",
    )
    scan_network_segmentation: bool = Field(
        default=True,
        description="Validate CDE network segmentation",
    )
    scan_encryption: bool = Field(
        default=True,
        description="Validate cardholder data encryption",
    )
    scan_access_controls: bool = Field(
        default=True,
        description="Validate access control configurations",
    )
    metadata: dict[str, Any] = Field(default_factory=dict)


class PCIControlResult(BaseModel):
    """Result for a single PCI DSS control."""

    requirement: PCIDSSRequirement
    control_id: str
    control_description: str
    status: PCIControlStatus
    evidence: str
    remediation_guidance: str | None = None
    risk_level: str = Field(description="low | medium | high | critical")


class PCIDSSScanResponse(BaseModel):
    """PCI DSS control scan response."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    scope_description: str
    pci_dss_version: str
    scan_started_at: datetime
    scan_completed_at: datetime
    total_controls: int
    compliant_controls: int
    non_compliant_controls: int
    compensating_controls: int
    compliance_percentage: float
    control_results: list[PCIControlResult]
    qsa_ready: bool = Field(description="Whether scan results are ready for QSA review")

    model_config = {"from_attributes": True}


# ============================================================================
# DORA schemas
# ============================================================================


class DORAStatusResponse(BaseModel):
    """DORA ICT operational resilience status."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    assessment_date: datetime
    overall_status: DORAResilienceStatus
    ict_register_complete: bool
    testing_program_active: bool
    incident_reporting_configured: bool
    third_party_oversight_active: bool
    information_sharing_active: bool
    rto_meets_threshold: bool
    rpo_meets_threshold: bool
    current_rto_hours: float | None
    current_rpo_hours: float | None
    open_gaps: list[str]
    next_assessment_date: datetime
    created_at: datetime

    model_config = {"from_attributes": True}


# ============================================================================
# Synthetic transaction schemas
# ============================================================================


class SyntheticTransactionRequest(BaseModel):
    """Request to generate synthetic financial transactions."""

    num_transactions: int = Field(
        ge=1,
        le=1_000_000,
        description="Number of synthetic transactions to generate",
    )
    transaction_types: list[TransactionType] = Field(
        default_factory=lambda: [TransactionType.PAYMENT, TransactionType.TRANSFER],
        description="Transaction types to include in the dataset",
    )
    fraud_rate: float = Field(
        default=0.02,
        ge=0.0,
        le=0.5,
        description="Fraction of transactions to label as fraudulent (0.0–0.5)",
    )
    currency: str = Field(
        default="USD",
        description="ISO 4217 currency code for transaction amounts",
    )
    amount_min: Decimal = Field(
        default=Decimal("0.01"),
        description="Minimum transaction amount",
    )
    amount_max: Decimal = Field(
        default=Decimal("1000000.00"),
        description="Maximum transaction amount",
    )
    num_accounts: int = Field(
        default=1000,
        ge=10,
        description="Number of synthetic account identities to use",
    )
    date_range_days: int = Field(
        default=365,
        ge=1,
        le=3650,
        description="Date range in days for transaction timestamps",
    )
    include_merchant_data: bool = Field(
        default=True,
        description="Include synthetic merchant name and MCC code",
    )
    include_device_data: bool = Field(
        default=False,
        description="Include synthetic device fingerprint data",
    )
    pii_masked: bool = Field(
        default=True,
        description="Mask all PII fields in output (recommended)",
    )
    seed: int | None = Field(
        default=None,
        description="Random seed for reproducible generation",
    )
    metadata: dict[str, Any] = Field(default_factory=dict)


class SyntheticTransactionResponse(BaseModel):
    """Response for synthetic transaction generation."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    num_transactions: int
    transaction_types: list[TransactionType]
    fraud_rate: float
    currency: str
    status: str = Field(description="pending | running | completed | failed")
    output_uri: str | None = Field(default=None, description="Storage URI for generated dataset")
    fraud_count: int | None = None
    legitimate_count: int | None = None
    created_at: datetime
    completed_at: datetime | None = None

    model_config = {"from_attributes": True}


# ============================================================================
# Regulatory report schemas
# ============================================================================


class RegulatoryReportRequest(BaseModel):
    """Request to generate a regulatory report."""

    regulator: RegulatoryBody = Field(description="Target regulatory body")
    report_type: ReportType = Field(description="Type of regulatory report")
    reporting_period_start: datetime = Field(description="Start of reporting period")
    reporting_period_end: datetime = Field(description="End of reporting period")
    entity_name: str = Field(description="Legal entity name for the report")
    entity_crd_number: str | None = Field(
        default=None,
        description="FINRA CRD number (required for FINRA reports)",
    )
    include_ai_disclosure: bool = Field(
        default=True,
        description="Include SEC AI governance disclosure section",
    )
    model_inventory_ids: list[uuid.UUID] = Field(
        default_factory=list,
        description="Model risk assessment IDs to include in AI disclosure",
    )
    sox_evidence_ids: list[uuid.UUID] = Field(
        default_factory=list,
        description="SOX evidence IDs to reference in attestation sections",
    )
    additional_sections: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional custom sections to include in the report",
    )
    metadata: dict[str, Any] = Field(default_factory=dict)


class RegulatoryReportResponse(BaseModel):
    """Generated regulatory report response."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    regulator: RegulatoryBody
    report_type: ReportType
    reporting_period_start: datetime
    reporting_period_end: datetime
    entity_name: str
    status: str = Field(description="pending | generating | completed | failed")
    output_uri: str | None = Field(default=None, description="Storage URI for generated report")
    report_format: str = Field(default="PDF", description="Output format: PDF | XBRL | JSON")
    page_count: int | None = None
    created_at: datetime
    completed_at: datetime | None = None

    model_config = {"from_attributes": True}


class RegulatoryReportListResponse(BaseModel):
    """Paginated list of regulatory reports."""

    items: list[RegulatoryReportResponse]
    total: int
    page: int
    page_size: int
