"""SQLAlchemy repository adapters for aumos-finserv-overlay.

Each repository provides tenant-isolated CRUD operations for a single
aggregate root model, using asyncpg-backed async sessions.
"""

import uuid
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from aumos_common.observability import get_logger

from aumos_finserv_overlay.core.models import (
    DORAAssessment,
    ModelRiskAssessment,
    PCIDSSControl,
    RegulatoryReport,
    SOXEvidence,
    SyntheticTransaction,
)

logger = get_logger(__name__)


class SOXEvidenceRepository:
    """Repository for fsv_sox_evidence table operations."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialise with an injected async session.

        Args:
            session: SQLAlchemy async session from DI.
        """
        self._session = session

    async def create(self, evidence: SOXEvidence) -> SOXEvidence:
        """Persist a new SOX evidence record.

        Args:
            evidence: SOXEvidence ORM instance to persist.

        Returns:
            Persisted SOXEvidence with id and timestamps populated.
        """
        self._session.add(evidence)
        await self._session.flush()
        await self._session.refresh(evidence)
        logger.debug("Created SOX evidence", evidence_id=str(evidence.id))
        return evidence

    async def get_by_id(
        self,
        evidence_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> SOXEvidence | None:
        """Retrieve a SOX evidence record by primary key with tenant guard.

        Args:
            evidence_id: Evidence record UUID.
            tenant_id: Tenant guard for row-level isolation.

        Returns:
            SOXEvidence instance or None if not found / wrong tenant.
        """
        stmt = select(SOXEvidence).where(
            SOXEvidence.id == evidence_id,
            SOXEvidence.tenant_id == tenant_id,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        control_area: str | None,
        page: int,
        page_size: int,
    ) -> tuple[list[SOXEvidence], int]:
        """List SOX evidence records for a tenant with optional area filter.

        Args:
            tenant_id: Tenant identifier.
            control_area: Optional COSO control area filter.
            page: 1-based page number.
            page_size: Records per page.

        Returns:
            Tuple of (records list, total count).
        """
        from sqlalchemy import func

        base_stmt = select(SOXEvidence).where(SOXEvidence.tenant_id == tenant_id)
        if control_area is not None:
            base_stmt = base_stmt.where(SOXEvidence.control_area == control_area)

        count_stmt = select(func.count()).select_from(base_stmt.subquery())
        total_result = await self._session.execute(count_stmt)
        total = total_result.scalar_one()

        data_stmt = (
            base_stmt.order_by(SOXEvidence.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        data_result = await self._session.execute(data_stmt)
        records = list(data_result.scalars().all())
        return records, total

    async def update_status(self, evidence_id: uuid.UUID, status: str) -> None:
        """Update the review status of a SOX evidence record.

        Args:
            evidence_id: Evidence record UUID.
            status: New status value.
        """
        stmt = (
            update(SOXEvidence)
            .where(SOXEvidence.id == evidence_id)
            .values(status=status)
        )
        await self._session.execute(stmt)


class ModelRiskRepository:
    """Repository for fsv_model_risk_assessments table operations."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, assessment: ModelRiskAssessment) -> ModelRiskAssessment:
        """Persist a new model risk assessment.

        Args:
            assessment: ModelRiskAssessment ORM instance.

        Returns:
            Persisted instance with id and timestamps.
        """
        self._session.add(assessment)
        await self._session.flush()
        await self._session.refresh(assessment)
        logger.debug("Created model risk assessment", assessment_id=str(assessment.id))
        return assessment

    async def get_by_id(
        self,
        assessment_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> ModelRiskAssessment | None:
        """Retrieve a model risk assessment by primary key.

        Args:
            assessment_id: Assessment UUID.
            tenant_id: Tenant guard.

        Returns:
            ModelRiskAssessment or None.
        """
        stmt = select(ModelRiskAssessment).where(
            ModelRiskAssessment.id == assessment_id,
            ModelRiskAssessment.tenant_id == tenant_id,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        risk_tier: str | None,
        page: int,
        page_size: int,
    ) -> tuple[list[ModelRiskAssessment], int]:
        """List model risk assessments for a tenant.

        Args:
            tenant_id: Tenant identifier.
            risk_tier: Optional tier filter.
            page: 1-based page number.
            page_size: Records per page.

        Returns:
            Tuple of (records list, total count).
        """
        from sqlalchemy import func

        base_stmt = select(ModelRiskAssessment).where(
            ModelRiskAssessment.tenant_id == tenant_id
        )
        if risk_tier is not None:
            base_stmt = base_stmt.where(ModelRiskAssessment.risk_tier == risk_tier)

        count_stmt = select(func.count()).select_from(base_stmt.subquery())
        total = (await self._session.execute(count_stmt)).scalar_one()

        data_stmt = (
            base_stmt.order_by(ModelRiskAssessment.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        records = list((await self._session.execute(data_stmt)).scalars().all())
        return records, total

    async def update_validation_status(
        self,
        assessment_id: uuid.UUID,
        status: str,
    ) -> None:
        """Update validation status of a model risk assessment.

        Args:
            assessment_id: Assessment UUID.
            status: New validation status.
        """
        stmt = (
            update(ModelRiskAssessment)
            .where(ModelRiskAssessment.id == assessment_id)
            .values(validation_status=status)
        )
        await self._session.execute(stmt)


class PCIDSSRepository:
    """Repository for fsv_pci_controls table operations."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create_batch(
        self,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        controls: list[PCIDSSControl],
    ) -> list[PCIDSSControl]:
        """Persist a batch of PCI DSS control records.

        Args:
            scan_id: UUID grouping this scan session.
            tenant_id: Owning tenant.
            controls: PCIDSSControl ORM instances to persist.

        Returns:
            List of persisted instances.
        """
        for control in controls:
            control.scan_id = scan_id
            control.tenant_id = tenant_id
            self._session.add(control)

        await self._session.flush()
        for control in controls:
            await self._session.refresh(control)

        logger.debug(
            "Created PCI DSS control batch",
            scan_id=str(scan_id),
            count=len(controls),
        )
        return controls

    async def get_by_scan_id(
        self,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> list[PCIDSSControl]:
        """Retrieve all control results for a scan session.

        Args:
            scan_id: Scan session UUID.
            tenant_id: Tenant guard.

        Returns:
            List of PCIDSSControl instances.
        """
        stmt = select(PCIDSSControl).where(
            PCIDSSControl.scan_id == scan_id,
            PCIDSSControl.tenant_id == tenant_id,
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())


class DORARepository:
    """Repository for fsv_dora_assessments table operations."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, assessment: DORAAssessment) -> DORAAssessment:
        """Persist a DORA assessment record.

        Args:
            assessment: DORAAssessment ORM instance.

        Returns:
            Persisted instance.
        """
        self._session.add(assessment)
        await self._session.flush()
        await self._session.refresh(assessment)
        logger.debug("Created DORA assessment", assessment_id=str(assessment.id))
        return assessment

    async def get_latest_by_tenant(self, tenant_id: uuid.UUID) -> DORAAssessment | None:
        """Retrieve the most recent DORA assessment for a tenant.

        Args:
            tenant_id: Tenant identifier.

        Returns:
            Most recent DORAAssessment or None.
        """
        stmt = (
            select(DORAAssessment)
            .where(DORAAssessment.tenant_id == tenant_id)
            .order_by(DORAAssessment.created_at.desc())
            .limit(1)
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        page: int,
        page_size: int,
    ) -> tuple[list[DORAAssessment], int]:
        """List DORA assessments for a tenant.

        Args:
            tenant_id: Tenant identifier.
            page: 1-based page number.
            page_size: Records per page.

        Returns:
            Tuple of (records list, total count).
        """
        from sqlalchemy import func

        base_stmt = select(DORAAssessment).where(DORAAssessment.tenant_id == tenant_id)
        total = (
            await self._session.execute(select(func.count()).select_from(base_stmt.subquery()))
        ).scalar_one()

        data_stmt = (
            base_stmt.order_by(DORAAssessment.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        records = list((await self._session.execute(data_stmt)).scalars().all())
        return records, total


class SyntheticTransactionRepository:
    """Repository for fsv_synthetic_transactions table operations."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, job: SyntheticTransaction) -> SyntheticTransaction:
        """Persist a synthetic transaction generation job.

        Args:
            job: SyntheticTransaction ORM instance.

        Returns:
            Persisted instance.
        """
        self._session.add(job)
        await self._session.flush()
        await self._session.refresh(job)
        logger.debug("Created synthetic transaction job", job_id=str(job.id))
        return job

    async def get_by_id(
        self,
        job_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> SyntheticTransaction | None:
        """Retrieve a synthetic transaction job by ID.

        Args:
            job_id: Job UUID.
            tenant_id: Tenant guard.

        Returns:
            SyntheticTransaction or None.
        """
        stmt = select(SyntheticTransaction).where(
            SyntheticTransaction.id == job_id,
            SyntheticTransaction.tenant_id == tenant_id,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def update_completion(
        self,
        job_id: uuid.UUID,
        output_uri: str,
        fraud_count: int,
        legitimate_count: int,
    ) -> None:
        """Mark a synthetic transaction job as completed.

        Args:
            job_id: Job UUID.
            output_uri: Storage URI for generated dataset.
            fraud_count: Number of fraudulent transactions generated.
            legitimate_count: Number of legitimate transactions generated.
        """
        stmt = (
            update(SyntheticTransaction)
            .where(SyntheticTransaction.id == job_id)
            .values(
                status="completed",
                output_uri=output_uri,
                fraud_count=fraud_count,
                legitimate_count=legitimate_count,
            )
        )
        await self._session.execute(stmt)

    async def update_failure(self, job_id: uuid.UUID, error_message: str) -> None:
        """Mark a synthetic transaction job as failed.

        Args:
            job_id: Job UUID.
            error_message: Error description.
        """
        stmt = (
            update(SyntheticTransaction)
            .where(SyntheticTransaction.id == job_id)
            .values(status="failed", error_message=error_message)
        )
        await self._session.execute(stmt)


class RegulatoryReportRepository:
    """Repository for fsv_regulatory_reports table operations."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, report: RegulatoryReport) -> RegulatoryReport:
        """Persist a regulatory report record.

        Args:
            report: RegulatoryReport ORM instance.

        Returns:
            Persisted instance.
        """
        self._session.add(report)
        await self._session.flush()
        await self._session.refresh(report)
        logger.debug(
            "Created regulatory report",
            report_id=str(report.id),
            regulator=report.regulator,
        )
        return report

    async def get_by_id(
        self,
        report_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> RegulatoryReport | None:
        """Retrieve a regulatory report by primary key.

        Args:
            report_id: Report UUID.
            tenant_id: Tenant guard.

        Returns:
            RegulatoryReport or None.
        """
        stmt = select(RegulatoryReport).where(
            RegulatoryReport.id == report_id,
            RegulatoryReport.tenant_id == tenant_id,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        regulator: str | None,
        page: int,
        page_size: int,
    ) -> tuple[list[RegulatoryReport], int]:
        """List regulatory reports for a tenant.

        Args:
            tenant_id: Tenant identifier.
            regulator: Optional regulator filter.
            page: 1-based page number.
            page_size: Records per page.

        Returns:
            Tuple of (records list, total count).
        """
        from sqlalchemy import func

        base_stmt = select(RegulatoryReport).where(RegulatoryReport.tenant_id == tenant_id)
        if regulator is not None:
            base_stmt = base_stmt.where(RegulatoryReport.regulator == regulator)

        total = (
            await self._session.execute(select(func.count()).select_from(base_stmt.subquery()))
        ).scalar_one()

        data_stmt = (
            base_stmt.order_by(RegulatoryReport.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        records = list((await self._session.execute(data_stmt)).scalars().all())
        return records, total

    async def update_completion(
        self,
        report_id: uuid.UUID,
        output_uri: str,
        page_count: int,
        report_format: str,
    ) -> None:
        """Mark a regulatory report as completed.

        Args:
            report_id: Report UUID.
            output_uri: Storage URI for generated report document.
            page_count: Number of pages in the generated report.
            report_format: Output format (PDF | XBRL | JSON).
        """
        stmt = (
            update(RegulatoryReport)
            .where(RegulatoryReport.id == report_id)
            .values(
                status="completed",
                output_uri=output_uri,
                page_count=page_count,
                report_format=report_format,
            )
        )
        await self._session.execute(stmt)
