"""SWIFT Customer Security Programme (CSP) compliance scanner.

GAP-300: SWIFT CSP Compliance Scanning.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)


class CSPControlType(str, Enum):
    """SWIFT CSP CSCF v2025 control type classification."""

    MANDATORY = "mandatory"
    ADVISORY = "advisory"


@dataclass
class CSPControl:
    """SWIFT CSP CSCF v2025 control definition."""

    control_id: str
    title: str
    control_type: CSPControlType
    description: str
    config_assertions: list[str]


# SWIFT CSCF v2025 mandatory controls (27 controls)
MANDATORY_CONTROLS: list[CSPControl] = [
    CSPControl("1.1", "SWIFT Environment Protection", CSPControlType.MANDATORY,
               "Ensure SWIFT infrastructure is protected from general IT environment",
               ["network_segmentation_enabled", "dmz_configured"]),
    CSPControl("1.2", "Operating System Privileged Account Control", CSPControlType.MANDATORY,
               "Restrict and control allocation of privileged accounts",
               ["privileged_accounts_inventoried", "mfa_on_privileged_accounts"]),
    CSPControl("1.3", "Virtualisation Platform Security", CSPControlType.MANDATORY,
               "Secure virtualisation platform and infrastructure",
               ["hypervisor_patched", "vm_isolation_enforced"]),
    CSPControl("1.4", "Restriction of Internet Access", CSPControlType.MANDATORY,
               "Protect SWIFT infrastructure from internet-originated threats",
               ["internet_access_restricted", "proxy_enforced"]),
    CSPControl("2.1", "Internal Data Flow Security", CSPControlType.MANDATORY,
               "Protect and control data flow for SWIFT messaging",
               ["tls_1_2_minimum", "message_signing_enforced"]),
    CSPControl("2.2", "Security Updates", CSPControlType.MANDATORY,
               "Minimise occurrence of known technical vulnerabilities",
               ["patch_cycle_30_days", "vulnerability_scanning_enabled"]),
    CSPControl("2.3", "System Hardening", CSPControlType.MANDATORY,
               "Reduce attack surface by hardening systems",
               ["cis_hardening_applied", "unnecessary_services_disabled"]),
    CSPControl("2.4", "Back Office Data Flow Security", CSPControlType.MANDATORY,
               "Protect confidential back-office business data flows",
               ["back_office_segmented", "encryption_in_transit"]),
    CSPControl("2.5", "External Transmission Data Protection", CSPControlType.MANDATORY,
               "Protect the confidentiality of SWIFT-related data",
               ["data_encrypted_at_rest", "key_management_compliant"]),
    CSPControl("2.6", "Operator Session Confidentiality and Integrity", CSPControlType.MANDATORY,
               "Protect interactive operator sessions",
               ["session_timeout_configured", "session_encryption_enabled"]),
    CSPControl("2.7", "Vulnerability Scanning", CSPControlType.MANDATORY,
               "Identify security vulnerabilities within the SWIFT environment",
               ["quarterly_vuln_scans", "critical_patches_applied"]),
    CSPControl("2.8", "Critical Activity Outsourcing", CSPControlType.MANDATORY,
               "Protect SWIFT infrastructure when critical activities are outsourced",
               ["vendor_risk_assessment", "sla_security_requirements"]),
    CSPControl("2.9", "Transaction Business Controls", CSPControlType.MANDATORY,
               "Restrict transactions based on business rules",
               ["transaction_limits_configured", "beneficiary_whitelist"]),
    CSPControl("5.1", "Logical Access Controls", CSPControlType.MANDATORY,
               "Enforce security controls on SWIFT-related application access",
               ["rbac_enforced", "least_privilege_applied"]),
    CSPControl("5.2", "Token Management", CSPControlType.MANDATORY,
               "Ensure proper use of physical and logical tokens",
               ["hardware_tokens_required", "token_lifecycle_managed"]),
    CSPControl("5.3", "Staff Screening Process", CSPControlType.MANDATORY,
               "Verify background and qualifications of SWIFT staff",
               ["background_checks_performed", "annual_training_completed"]),
    CSPControl("5.4", "Physical and Logical Password Storage", CSPControlType.MANDATORY,
               "Protect recorded passwords",
               ["password_vault_used", "default_passwords_changed"]),
    CSPControl("6.1", "Cybersecurity Training", CSPControlType.MANDATORY,
               "Ensure all staff are trained in cybersecurity practices",
               ["annual_security_training", "phishing_awareness_training"]),
    CSPControl("6.2", "Software Integrity", CSPControlType.MANDATORY,
               "Ensure integrity of SWIFT software",
               ["code_signing_verified", "integrity_checks_on_install"]),
    CSPControl("6.3", "Database Integrity", CSPControlType.MANDATORY,
               "Ensure integrity of SWIFT database",
               ["db_access_logging", "db_integrity_checks_scheduled"]),
    CSPControl("6.4", "Logging and Monitoring", CSPControlType.MANDATORY,
               "Record and monitor security events",
               ["siem_configured", "log_retention_90_days_minimum"]),
    CSPControl("6.5", "Intrusion Detection", CSPControlType.MANDATORY,
               "Detect anomalous activity within SWIFT systems",
               ["ids_deployed", "ids_signatures_updated"]),
    CSPControl("7.1", "Cyber Incident Response Planning", CSPControlType.MANDATORY,
               "Ensure cyber incidents are handled appropriately",
               ["incident_response_plan_documented", "tabletop_exercises_annual"]),
    CSPControl("7.2", "Security Testing", CSPControlType.MANDATORY,
               "Validate operational security configuration",
               ["penetration_testing_annual", "red_team_exercises"]),
    CSPControl("7.3", "Penetration Testing", CSPControlType.MANDATORY,
               "Perform vulnerability assessments and penetration testing",
               ["pen_test_documented", "findings_remediated"]),
    CSPControl("7.4", "Scenario Risk Assessment", CSPControlType.MANDATORY,
               "Identify and address risks through scenario planning",
               ["risk_scenarios_documented", "risk_acceptance_process"]),
    CSPControl("7.5", "Third-Party Risk Management", CSPControlType.MANDATORY,
               "Manage risk introduced by third-party providers",
               ["third_party_inventory", "annual_vendor_assessments"]),
]


@dataclass
class CSPScanResult:
    """SWIFT CSP compliance scan result."""

    passed_controls: list[str] = field(default_factory=list)
    failed_controls: list[str] = field(default_factory=list)
    not_applicable_controls: list[str] = field(default_factory=list)
    mandatory_score: float = 0.0
    advisory_score: float = 0.0
    overall_compliant: bool = False
    findings: list[dict[str, Any]] = field(default_factory=list)


class SWIFTCSPChecker:
    """SWIFT Customer Security Programme CSCF v2025 compliance scanner.

    All checks are configuration assertions — no external SWIFT API calls.
    Mandatory compliance requires 27/27 mandatory controls to pass.
    """

    def scan(self, environment_config: dict[str, Any]) -> CSPScanResult:
        """Execute a full SWIFT CSP CSCF v2025 compliance scan.

        Args:
            environment_config: Dict of assertion names mapped to bool values.
                                 Keys correspond to config_assertions in MANDATORY_CONTROLS.

        Returns:
            CSPScanResult with pass/fail per control and overall score.
        """
        result = CSPScanResult()

        for control in MANDATORY_CONTROLS:
            assertion_results = [
                bool(environment_config.get(assertion, False))
                for assertion in control.config_assertions
            ]
            passed = all(assertion_results)

            if passed:
                result.passed_controls.append(control.control_id)
            else:
                result.failed_controls.append(control.control_id)
                failed_assertions = [
                    a for a, r in zip(control.config_assertions, assertion_results) if not r
                ]
                result.findings.append({
                    "control_id": control.control_id,
                    "title": control.title,
                    "type": control.control_type.value,
                    "failed_assertions": failed_assertions,
                    "remediation": f"Implement: {', '.join(failed_assertions)}",
                })

        mandatory_passed = len([c for c in result.passed_controls if c in
                                 {ctrl.control_id for ctrl in MANDATORY_CONTROLS}])
        result.mandatory_score = mandatory_passed / len(MANDATORY_CONTROLS) if MANDATORY_CONTROLS else 0.0
        result.overall_compliant = len(result.failed_controls) == 0

        logger.info(
            "swift_csp_scan_complete",
            mandatory_score=result.mandatory_score,
            compliant=result.overall_compliant,
            failed_count=len(result.failed_controls),
        )
        return result
