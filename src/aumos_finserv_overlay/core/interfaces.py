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
