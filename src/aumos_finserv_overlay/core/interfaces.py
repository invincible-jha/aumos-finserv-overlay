"""Protocol interfaces for aumos-finserv-overlay.

Defines structural subtypes (Protocols) for all major service interfaces.
Adapters must conform to these protocols, enabling dependency injection
and test substitution without inheritance.
"""

import uuid
from decimal import Decimal
from typing import Any, Protocol, runtime_checkable

from aumos_finserv_overlay.api.schemas import (
    DORAStatusResponse,
    ModelRiskAssessmentRequest,
    ModelRiskAssessmentResponse,
    PCIDSSScanRequest,
    PCIDSSScanResponse,
    RegulatoryReportRequest,
    SOXEvidenceRequest,
    SOXEvidenceResponse,
    SyntheticTransactionRequest,
)


@runtime_checkable
class SOXEvidenceRepositoryProtocol(Protocol):
    """Protocol for SOX evidence persistence.

    Implementations provide CRUD operations for fsv_sox_evidence records
    with tenant isolation enforced at every operation.
    """

    async def create(self, evidence: Any) -> Any:
        """Persist a new SOX evidence record.

        Returns:
            Created SOXEvidence model instance with id and timestamps.
        """
        ...

    async def get_by_id(
        self,
        evidence_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> Any | None:
        """Retrieve a SOX evidence record by primary key.

        Returns:
            SOXEvidence instance or None if not found.
        """
        ...

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        control_area: str | None,
        page: int,
        page_size: int,
    ) -> tuple[list[Any], int]:
        """List SOX evidence records for a tenant with optional area filter.

        Returns:
            Tuple of (records list, total count).
        """
        ...

    async def update_status(
        self,
        evidence_id: uuid.UUID,
        status: str,
    ) -> None:
        """Update the review status of a SOX evidence record.

        Args:
            evidence_id: Evidence record UUID.
            status: New status value.
        """
        ...


@runtime_checkable
class ModelRiskRepositoryProtocol(Protocol):
    """Protocol for SR 11-7 model risk assessment persistence."""

    async def create(self, assessment: Any) -> Any:
        """Persist a new model risk assessment."""
        ...

    async def get_by_id(
        self,
        assessment_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> Any | None:
        """Retrieve a model risk assessment by primary key."""
        ...

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        risk_tier: str | None,
        page: int,
        page_size: int,
    ) -> tuple[list[Any], int]:
        """List model risk assessments for a tenant with optional tier filter."""
        ...

    async def update_validation_status(
        self,
        assessment_id: uuid.UUID,
        status: str,
    ) -> None:
        """Update the validation status of a model risk assessment."""
        ...


@runtime_checkable
class PCIDSSRepositoryProtocol(Protocol):
    """Protocol for PCI DSS control record persistence."""

    async def create_batch(
        self,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        controls: list[Any],
    ) -> list[Any]:
        """Persist a batch of PCI DSS control scan results.

        Args:
            scan_id: UUID grouping controls from this scan session.
            tenant_id: Owning tenant.
            controls: List of PCIDSSControl model instances.

        Returns:
            List of created PCIDSSControl instances.
        """
        ...

    async def get_by_scan_id(
        self,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> list[Any]:
        """Retrieve all control results for a scan session."""
        ...


@runtime_checkable
class DORARepositoryProtocol(Protocol):
    """Protocol for DORA assessment persistence."""

    async def create(self, assessment: Any) -> Any:
        """Persist a DORA assessment record."""
        ...

    async def get_latest_by_tenant(self, tenant_id: uuid.UUID) -> Any | None:
        """Retrieve the most recent DORA assessment for a tenant."""
        ...

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        page: int,
        page_size: int,
    ) -> tuple[list[Any], int]:
        """List DORA assessments for a tenant."""
        ...


@runtime_checkable
class SyntheticTransactionRepositoryProtocol(Protocol):
    """Protocol for synthetic transaction job persistence."""

    async def create(self, job: Any) -> Any:
        """Persist a synthetic transaction generation job."""
        ...

    async def get_by_id(
        self,
        job_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> Any | None:
        """Retrieve a synthetic transaction job by ID."""
        ...

    async def update_completion(
        self,
        job_id: uuid.UUID,
        output_uri: str,
        fraud_count: int,
        legitimate_count: int,
    ) -> None:
        """Mark a job as completed with output details."""
        ...

    async def update_failure(self, job_id: uuid.UUID, error_message: str) -> None:
        """Mark a job as failed with error details."""
        ...


@runtime_checkable
class RegulatoryReportRepositoryProtocol(Protocol):
    """Protocol for regulatory report persistence."""

    async def create(self, report: Any) -> Any:
        """Persist a regulatory report record."""
        ...

    async def get_by_id(
        self,
        report_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> Any | None:
        """Retrieve a regulatory report by primary key."""
        ...

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        regulator: str | None,
        page: int,
        page_size: int,
    ) -> tuple[list[Any], int]:
        """List regulatory reports for a tenant."""
        ...

    async def update_completion(
        self,
        report_id: uuid.UUID,
        output_uri: str,
        page_count: int,
        report_format: str,
    ) -> None:
        """Mark a report as completed with output details."""
        ...


@runtime_checkable
class TransactionGeneratorProtocol(Protocol):
    """Protocol for synthetic financial transaction generation.

    Implementations produce statistically realistic synthetic transaction
    datasets with configurable fraud injection rates, transaction types,
    and demographic distributions.
    """

    async def generate(
        self,
        request: SyntheticTransactionRequest,
    ) -> tuple[bytes, int, int]:
        """Generate synthetic transactions and return serialised output.

        Args:
            request: Transaction generation parameters.

        Returns:
            Tuple of (CSV/JSON bytes, fraud_count, legitimate_count).
        """
        ...


@runtime_checkable
class ReportGeneratorProtocol(Protocol):
    """Protocol for regulatory report document generation.

    Implementations render report templates into PDF, XBRL, or JSON
    output for submission to SEC, CFPB, FINRA, OCC, FDIC, or FRB.
    """

    async def generate_report(
        self,
        request: RegulatoryReportRequest,
        tenant_id: uuid.UUID,
        model_assessments: list[dict[str, Any]],
        sox_evidence_items: list[dict[str, Any]],
    ) -> tuple[bytes, str, int]:
        """Render a regulatory report document.

        Args:
            request: Report generation parameters.
            tenant_id: Tenant owning the report.
            model_assessments: SR 11-7 assessment data to include.
            sox_evidence_items: SOX evidence items to reference.

        Returns:
            Tuple of (document bytes, format string, page count).
        """
        ...


@runtime_checkable
class StorageProtocol(Protocol):
    """Protocol for object storage adapter."""

    async def upload(
        self,
        key: str,
        content: bytes,
        content_type: str,
    ) -> str:
        """Upload content to object storage.

        Args:
            key: Storage key/path.
            content: Binary content to upload.
            content_type: MIME type of the content.

        Returns:
            Storage URI for the uploaded object.
        """
        ...

    async def get_signed_url(self, uri: str, expires_seconds: int = 3600) -> str:
        """Generate a pre-signed download URL.

        Args:
            uri: Storage URI returned by upload.
            expires_seconds: URL expiry time in seconds.

        Returns:
            Pre-signed HTTPS URL for direct download.
        """
        ...


@runtime_checkable
class SOXComplianceAdapterProtocol(Protocol):
    """Protocol for SOX compliance domain logic operations.

    Implementations provide PCAOB/COSO-aligned control definitions,
    evidence assessment, deficiency classification, and audit trail
    generation per SOX Sections 302 and 404.
    """

    def define_control(
        self,
        control_id: str,
        control_area: str,
        description: str,
        is_key_control: bool,
    ) -> dict: ...

    def collect_evidence(
        self,
        control_id: str,
        evidence_type: str,
        evidence_description: str,
        artifacts: list[str],
    ) -> dict: ...

    def test_control_effectiveness(
        self,
        control_id: str,
        test_results: list[dict],
        sample_size: int,
    ) -> dict: ...

    def classify_deficiency(
        self,
        test_result: dict,
        is_key_control: bool,
    ) -> dict: ...

    def generate_management_assertion(
        self,
        control_results: list[dict],
        reporting_period_start: str,
        reporting_period_end: str,
        entity_name: str,
    ) -> dict: ...

    def generate_audit_trail(self, evidence_chain: list[dict]) -> dict: ...

    def map_sox_articles(self) -> dict: ...


@runtime_checkable
class ModelRiskManagerProtocol(Protocol):
    """Protocol for SR 11-7 model risk management operations.

    Implementations manage model registration, validation requirements,
    performance monitoring, challenger model comparison, and MRM reporting
    per Federal Reserve SR 11-7 / OCC 2011-12 guidance.
    """

    def register_model(
        self,
        model_name: str,
        model_type: str,
        model_purpose: str,
        estimated_annual_exposure_usd: float,
        regulatory_capital_impact: bool,
        customer_facing: bool,
        business_line: str,
        known_limitations: list[str],
    ) -> dict: ...

    def map_validation_requirements(self, model_registration: dict) -> dict: ...

    def monitor_performance(
        self,
        model_id: str,
        performance_metrics: dict,
        monitoring_window_days: int,
    ) -> dict: ...

    def compare_challenger(
        self,
        champion_model_id: str,
        challenger_metrics: dict,
        champion_metrics: dict,
    ) -> dict: ...

    def generate_mrm_report(
        self,
        model_registrations: list[dict],
        reporting_period: str,
        institution_name: str,
    ) -> dict: ...


@runtime_checkable
class PCIDSSCheckerProtocol(Protocol):
    """Protocol for PCI DSS v4.0 compliance scanning operations.

    Implementations map PCI requirements, detect cardholder data exposure,
    validate encryption, verify access controls, and generate QSA-ready
    compliance reports.
    """

    def map_requirements(
        self,
        requirements_filter: list[str] | None,
    ) -> dict: ...

    def detect_cardholder_data(
        self,
        data_samples: list[str],
        scan_context: str,
    ) -> dict: ...

    def validate_encryption(self, encryption_config: dict) -> dict: ...

    def verify_access_controls(self, access_control_config: dict) -> dict: ...

    def check_network_segmentation(self, network_config: dict) -> dict: ...

    def generate_pci_compliance_report(
        self,
        scan_results: list[dict],
        entity_name: str,
        assessment_date: str,
    ) -> dict: ...


@runtime_checkable
class DORAComplianceAdapterProtocol(Protocol):
    """Protocol for DORA (EU 2022/2554) compliance assessment operations.

    Implementations assess ICT risk management, incident reporting readiness,
    resilience testing programs, and third-party ICT risk per DORA articles.
    """

    def assess_ict_risk_management(
        self,
        ict_inventory: list[dict],
        risk_tolerance: str,
    ) -> dict: ...

    def check_incident_reporting(
        self,
        incident_config: dict,
        entity_type: str,
    ) -> dict: ...

    def schedule_resilience_testing(
        self,
        entity_type: str,
        system_criticality: str,
        last_test_date: str | None,
    ) -> dict: ...

    def assess_third_party_risk(
        self,
        third_party_providers: list[dict],
        entity_classification: str,
    ) -> dict: ...

    def analyze_compliance_gaps(
        self,
        assessment_results: dict,
        entity_type: str,
    ) -> dict: ...


@runtime_checkable
class CreditRiskSynthesizerProtocol(Protocol):
    """Protocol for Basel III/IV credit risk synthetic data generation.

    Implementations generate synthetic loan portfolios with configurable
    credit quality distributions, default probability modeling, and
    stress scenario support for regulatory capital calculations.
    """

    def generate_loan_portfolio(
        self,
        num_loans: int,
        seed: int,
        asset_class_distribution: dict[str, float] | None,
        currency: str,
    ) -> tuple[bytes, dict]: ...

    def model_default_probability_distribution(
        self,
        credit_scores: list[int],
        macro_scenario: str,
    ) -> dict: ...


@runtime_checkable
class FraudPatternGeneratorProtocol(Protocol):
    """Protocol for fraud detection synthetic training data generation.

    Implementations generate realistic fraud pattern datasets with configurable
    typology distributions, fraud ring structures, and temporal patterns
    for AML and fraud model training.
    """

    def generate_fraud_dataset(
        self,
        num_transactions: int,
        fraud_rate: float,
        seed: int,
        fraud_typology_distribution: dict[str, float] | None,
    ) -> tuple[bytes, dict]: ...

    def generate_temporal_patterns(
        self,
        transactions: list[dict],
        pattern_type: str,
    ) -> dict: ...


@runtime_checkable
class AMLCheckerProtocol(Protocol):
    """Protocol for AML (Anti-Money Laundering) transaction analysis.

    Implementations analyze transactions for FATF red-flag typologies,
    perform customer risk scoring, run sanctions screening, and generate
    BSA/AML compliance reports.
    """

    def analyze_transaction_patterns(
        self,
        transactions: list[dict],
        customer_id: str,
        lookback_days: int,
    ) -> dict: ...

    def score_customer_risk(self, customer_profile: dict) -> dict: ...

    def screen_sanctions(
        self,
        entity_name: str,
        entity_type: str,
        country_of_origin: str,
    ) -> dict: ...

    def generate_aml_compliance_report(
        self,
        institution_name: str,
        reporting_period_start: str,
        reporting_period_end: str,
        transaction_volume: int,
        sars_filed: int,
        ctrs_filed: int,
    ) -> dict: ...

    def match_typologies(
        self,
        transaction_analysis: dict,
    ) -> dict: ...


@runtime_checkable
class FIPSValidatorProtocol(Protocol):
    """Protocol for FIPS 140-2 cryptographic module validation.

    Implementations verify algorithm compliance against NIST SP 800-131A,
    validate key lengths, check RNG compliance, define module boundaries,
    and generate CMVP certificate records.
    """

    def verify_algorithms(self, algorithms_in_use: list[str]) -> dict: ...

    def validate_key_lengths(
        self,
        key_configurations: list[dict],
    ) -> dict: ...

    def check_rng_compliance(self, rng_implementations: list[str]) -> dict: ...

    def define_module_boundary(
        self,
        module_name: str,
        included_components: list[str],
        excluded_components: list[str],
        module_type: str,
    ) -> dict: ...

    def generate_fips_certificate(
        self,
        module_name: str,
        module_version: str,
        security_level: int,
        algorithm_validation_results: dict,
        key_validation_results: dict,
    ) -> dict: ...
