"""Service-specific settings for aumos-finserv-overlay."""

from pydantic import Field
from pydantic_settings import SettingsConfigDict

from aumos_common.config import AumOSSettings


class Settings(AumOSSettings):
    """Financial services overlay configuration.

    Extends base AumOS settings with finserv-specific options for
    SOX evidence collection, model risk management, PCI DSS scanning,
    DORA assessments, synthetic transaction generation, and regulatory reporting.
    """

    service_name: str = "aumos-finserv-overlay"

    # SOX compliance
    sox_evidence_retention_days: int = Field(
        default=2555,
        description="SOX evidence retention period in days (7 years per PCAOB)",
    )
    sox_control_framework: str = Field(
        default="COSO",
        description="Internal control framework: COSO or COBIT",
    )
    sox_audit_trail_enabled: bool = Field(
        default=True,
        description="Enable immutable audit trail for all SOX evidence",
    )

    # SEC AI guidance
    sec_ai_guidance_version: str = Field(
        default="2024-01",
        description="SEC AI disclosure guidance version to apply",
    )
    sec_disclosure_materiality_threshold: float = Field(
        default=0.05,
        description="Materiality threshold for SEC AI risk disclosures (5%)",
    )

    # SR 11-7 model risk management
    sr117_validation_required: bool = Field(
        default=True,
        description="Require independent model validation per SR 11-7",
    )
    sr117_model_inventory_enabled: bool = Field(
        default=True,
        description="Maintain SR 11-7 model inventory",
    )
    sr117_high_risk_threshold: float = Field(
        default=0.7,
        description="Risk score threshold for SR 11-7 high-risk classification",
    )

    # PCI DSS
    pci_dss_version: str = Field(
        default="4.0",
        description="PCI DSS version for control scanning",
    )
    pci_scan_timeout_seconds: int = Field(
        default=300,
        description="PCI DSS control scan timeout in seconds",
    )
    pci_encryption_algorithm: str = Field(
        default="AES-256-GCM",
        description="Required encryption algorithm for cardholder data",
    )

    # DORA (Digital Operational Resilience Act)
    dora_ict_register_enabled: bool = Field(
        default=True,
        description="Maintain DORA ICT third-party service provider register",
    )
    dora_rto_threshold_hours: int = Field(
        default=4,
        description="Maximum RTO for critical ICT systems under DORA (hours)",
    )
    dora_rpo_threshold_hours: int = Field(
        default=1,
        description="Maximum RPO for critical ICT systems under DORA (hours)",
    )
    dora_incident_reporting_hours: int = Field(
        default=4,
        description="Hours after ICT incident to file initial DORA report",
    )

    # Synthetic transactions
    synth_max_transactions_per_request: int = Field(
        default=1_000_000,
        description="Maximum synthetic transactions per generation request",
    )
    synth_fraud_rate_default: float = Field(
        default=0.02,
        description="Default fraud injection rate for synthetic transactions (2%)",
    )
    synth_output_bucket: str = Field(
        default="aumos-finserv-synth",
        description="Object storage bucket for synthetic transaction output",
    )

    # Regulatory reporting
    report_output_bucket: str = Field(
        default="aumos-finserv-reports",
        description="Object storage bucket for regulatory report artifacts",
    )
    report_template_dir: str = Field(
        default="/app/templates/reports",
        description="Directory for Jinja2 regulatory report templates",
    )
    supported_regulators: list[str] = Field(
        default_factory=lambda: ["SEC", "CFPB", "FINRA", "OCC", "FDIC", "FRB"],
        description="Supported regulatory bodies for report generation",
    )

    model_config = SettingsConfigDict(env_prefix="AUMOS_FINSERV_")
