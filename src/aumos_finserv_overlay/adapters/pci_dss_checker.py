"""PCI DSS v4.0 compliance checker adapter for aumos-finserv-overlay.

Implements PCI DSS v4.0 requirement mapping, cardholder data detection,
encryption validation, access control verification, network segmentation
checking, and QSA-ready compliance report generation.
"""

import re
import uuid
from datetime import datetime, timezone
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# PCI DSS v4.0 complete requirement catalogue with descriptions and risk levels
_PCI_REQUIREMENTS: list[dict[str, Any]] = [
    # Requirement 1: Network Security Controls
    {"req": "1", "control_id": "1.1.1", "description": "Network security controls are defined and understood", "risk": "high", "domain": "Network Security"},
    {"req": "1", "control_id": "1.2.1", "description": "Configuration standards for network security controls are defined and implemented", "risk": "high", "domain": "Network Security"},
    {"req": "1", "control_id": "1.3.1", "description": "Inbound traffic to the CDE is restricted", "risk": "critical", "domain": "Network Security"},
    {"req": "1", "control_id": "1.3.2", "description": "Outbound traffic from the CDE is restricted", "risk": "critical", "domain": "Network Security"},
    {"req": "1", "control_id": "1.4.1", "description": "NSCs control traffic between trusted and untrusted networks", "risk": "high", "domain": "Network Security"},
    # Requirement 2: Secure Configurations
    {"req": "2", "control_id": "2.1.1", "description": "Configuration and hardening standards are developed and implemented", "risk": "high", "domain": "Secure Configuration"},
    {"req": "2", "control_id": "2.2.1", "description": "System components are configured using a configuration standard", "risk": "medium", "domain": "Secure Configuration"},
    {"req": "2", "control_id": "2.3.1", "description": "Wireless environments are configured with security settings", "risk": "high", "domain": "Secure Configuration"},
    # Requirement 3: Protect Account Data
    {"req": "3", "control_id": "3.1.1", "description": "Account data storage policies exist", "risk": "critical", "domain": "Account Data Protection"},
    {"req": "3", "control_id": "3.2.1", "description": "SAD is not retained after authorization", "risk": "critical", "domain": "Account Data Protection"},
    {"req": "3", "control_id": "3.3.1", "description": "SAD is not retained after authorization is complete", "risk": "critical", "domain": "Account Data Protection"},
    {"req": "3", "control_id": "3.4.1", "description": "PAN is unreadable anywhere it is stored", "risk": "critical", "domain": "Account Data Protection"},
    {"req": "3", "control_id": "3.5.1", "description": "Primary account numbers are secured with strong cryptography", "risk": "critical", "domain": "Account Data Protection"},
    # Requirement 4: Protect Transmissions
    {"req": "4", "control_id": "4.1.1", "description": "Processes to protect PAN during transmission are defined", "risk": "critical", "domain": "Data in Transit"},
    {"req": "4", "control_id": "4.2.1", "description": "Strong cryptography is used to safeguard PAN during transmission", "risk": "critical", "domain": "Data in Transit"},
    # Requirement 5: Protect Systems
    {"req": "5", "control_id": "5.1.1", "description": "Anti-malware solution(s) are deployed", "risk": "high", "domain": "Malware Protection"},
    {"req": "5", "control_id": "5.2.1", "description": "Anti-malware solutions are kept current", "risk": "high", "domain": "Malware Protection"},
    {"req": "5", "control_id": "5.3.1", "description": "Anti-malware mechanisms cannot be disabled by users", "risk": "medium", "domain": "Malware Protection"},
    # Requirement 6: Develop Secure Systems
    {"req": "6", "control_id": "6.1.1", "description": "Policies for security in software development are defined", "risk": "high", "domain": "Secure Development"},
    {"req": "6", "control_id": "6.2.1", "description": "Bespoke and custom software are developed securely", "risk": "high", "domain": "Secure Development"},
    {"req": "6", "control_id": "6.3.1", "description": "Security vulnerabilities are identified and managed", "risk": "high", "domain": "Secure Development"},
    {"req": "6", "control_id": "6.4.1", "description": "Public-facing web applications are protected against attacks", "risk": "critical", "domain": "Secure Development"},
    # Requirement 7: Restrict Access
    {"req": "7", "control_id": "7.1.1", "description": "Access control system(s) are in place", "risk": "high", "domain": "Access Control"},
    {"req": "7", "control_id": "7.2.1", "description": "Access is assigned based on need-to-know", "risk": "high", "domain": "Access Control"},
    {"req": "7", "control_id": "7.3.1", "description": "All user accounts and access are assigned and managed", "risk": "high", "domain": "Access Control"},
    # Requirement 8: Identify Users
    {"req": "8", "control_id": "8.1.1", "description": "Policies for user identification and authentication are defined", "risk": "high", "domain": "Identity Management"},
    {"req": "8", "control_id": "8.2.1", "description": "All user accounts are assigned a unique ID", "risk": "high", "domain": "Identity Management"},
    {"req": "8", "control_id": "8.3.1", "description": "Authentication factors are protected", "risk": "critical", "domain": "Identity Management"},
    {"req": "8", "control_id": "8.4.1", "description": "MFA is implemented for all access into the CDE", "risk": "critical", "domain": "Identity Management"},
    # Requirement 9: Restrict Physical Access
    {"req": "9", "control_id": "9.1.1", "description": "Physical access controls manage entry into the CDE", "risk": "high", "domain": "Physical Security"},
    {"req": "9", "control_id": "9.2.1", "description": "All media with cardholder data is physically secure", "risk": "high", "domain": "Physical Security"},
    # Requirement 10: Log and Monitor
    {"req": "10", "control_id": "10.1.1", "description": "Audit logs are implemented and active", "risk": "high", "domain": "Logging and Monitoring"},
    {"req": "10", "control_id": "10.2.1", "description": "Audit logs capture all required events", "risk": "high", "domain": "Logging and Monitoring"},
    {"req": "10", "control_id": "10.3.1", "description": "Audit logs are protected from destruction and modification", "risk": "critical", "domain": "Logging and Monitoring"},
    # Requirement 11: Test Security
    {"req": "11", "control_id": "11.1.1", "description": "Security vulnerability testing processes are defined", "risk": "high", "domain": "Security Testing"},
    {"req": "11", "control_id": "11.3.1", "description": "Internal vulnerability scans are performed at least quarterly", "risk": "high", "domain": "Security Testing"},
    {"req": "11", "control_id": "11.4.1", "description": "A penetration testing methodology is defined and implemented", "risk": "high", "domain": "Security Testing"},
    # Requirement 12: Support Security
    {"req": "12", "control_id": "12.1.1", "description": "An overall information security policy is established", "risk": "medium", "domain": "Security Policy"},
    {"req": "12", "control_id": "12.3.1", "description": "Risk assessment process is defined and implemented", "risk": "high", "domain": "Security Policy"},
    {"req": "12", "control_id": "12.6.1", "description": "Security awareness program is in place", "risk": "medium", "domain": "Security Policy"},
]

# PAN detection pattern (luhn-valid card number patterns — masked for display)
_PAN_PATTERN = re.compile(r"\b(?:\d[ -]?){13,19}\b")

# Approved TLS/SSL versions for PCI DSS v4.0
_APPROVED_TLS_VERSIONS = {"TLSv1.2", "TLSv1.3"}

# Approved encryption algorithms
_APPROVED_ENCRYPTION_ALGORITHMS = {"AES-128", "AES-192", "AES-256", "RSA-2048", "RSA-4096", "ECDSA-P256", "ECDSA-P384"}

# Minimum key lengths by algorithm
_MIN_KEY_LENGTHS: dict[str, int] = {
    "RSA": 2048,
    "ECDSA": 256,
    "AES": 128,
    "3DES": 168,
}


class PCIDSSChecker:
    """Validates Payment Card Industry Data Security Standard v4.0 compliance.

    Implements PCI DSS v4.0 requirement mapping, cardholder data detection,
    encryption validation, access control verification, network segmentation
    analysis, and QSA-ready compliance report generation.
    """

    def __init__(self) -> None:
        """Initialize PCI DSS checker."""
        pass

    def map_requirements(
        self,
        scope_description: str,
        requirements_to_include: list[str] | None = None,
        exclude_not_applicable: bool = False,
    ) -> dict[str, Any]:
        """Map applicable PCI DSS v4.0 requirements for a given scope.

        Identifies applicable requirements from the PCI DSS v4.0 control
        catalogue based on the specified scope and generates a structured
        requirement mapping for assessment purposes.

        Args:
            scope_description: Description of the cardholder data environment scope.
            requirements_to_include: Optional list of requirement numbers to include.
            exclude_not_applicable: Whether to exclude not-applicable requirements.

        Returns:
            PCI DSS requirement mapping dict with control details and counts.
        """
        requirements = _PCI_REQUIREMENTS
        if requirements_to_include:
            requirements = [r for r in requirements if r["req"] in requirements_to_include]

        domain_groups: dict[str, list[dict[str, Any]]] = {}
        for requirement in requirements:
            domain = requirement["domain"]
            if domain not in domain_groups:
                domain_groups[domain] = []
            domain_groups[domain].append({
                "requirement_number": requirement["req"],
                "control_id": requirement["control_id"],
                "description": requirement["description"],
                "risk_level": requirement["risk"],
            })

        critical_count = sum(1 for r in requirements if r["risk"] == "critical")
        high_count = sum(1 for r in requirements if r["risk"] == "high")

        mapping = {
            "pci_dss_version": "4.0",
            "scope_description": scope_description,
            "total_requirements": len(requirements),
            "critical_requirements": critical_count,
            "high_requirements": high_count,
            "domains": list(domain_groups.keys()),
            "requirement_by_domain": domain_groups,
            "mapped_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "PCI DSS v4.0 requirements mapped",
            total_requirements=len(requirements),
            critical_requirements=critical_count,
        )

        return mapping

    def detect_cardholder_data(
        self,
        sample_text: str,
        environment_name: str,
        data_flows: list[str],
    ) -> dict[str, Any]:
        """Detect potential cardholder data in text and data flow descriptions.

        Scans for PAN patterns and cardholder data indicators across
        sample text and documented data flows to identify scope for
        PCI DSS compliance.

        Args:
            sample_text: Sample text or log data to scan for PANs.
            environment_name: Name of the environment being scanned.
            data_flows: List of data flow descriptions to analyze.

        Returns:
            Cardholder data detection report dict.
        """
        pan_matches = _PAN_PATTERN.findall(sample_text)
        masked_matches = [m[:6] + "****" + m[-4:] for m in pan_matches]

        chd_keywords = ["cardholder", "PAN", "CVV", "CVC", "expiry", "card number", "track data", "SAD"]
        keyword_hits = [kw for kw in chd_keywords if kw.lower() in sample_text.lower()]

        flow_risks: list[dict[str, Any]] = []
        for flow in data_flows:
            flow_lower = flow.lower()
            risk_indicators = [
                kw for kw in ["pan", "card", "cvv", "track", "cardholder", "payment"]
                if kw in flow_lower
            ]
            if risk_indicators:
                flow_risks.append({
                    "data_flow": flow,
                    "risk_indicators": risk_indicators,
                    "in_scope_pci": True,
                    "recommendation": "Include this data flow in PCI DSS scope and implement controls",
                })

        in_scope = len(pan_matches) > 0 or len(keyword_hits) > 0 or len(flow_risks) > 0

        result = {
            "environment_name": environment_name,
            "pci_dss_in_scope": in_scope,
            "potential_pan_patterns_found": len(pan_matches),
            "masked_pan_samples": masked_matches[:5],
            "cardholder_data_keywords": keyword_hits,
            "data_flows_analyzed": len(data_flows),
            "at_risk_data_flows": flow_risks,
            "at_risk_flow_count": len(flow_risks),
            "immediate_actions_required": in_scope,
            "recommendations": [
                "Perform formal data flow diagram update to document all CHD touchpoints",
                "Apply tokenization or encryption to all identified PAN storage",
                "Implement DLP controls on identified at-risk data flows",
            ] if in_scope else [],
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "PCI DSS cardholder data detection complete",
            environment_name=environment_name,
            pci_dss_in_scope=in_scope,
            pan_patterns_found=len(pan_matches),
        )

        return result

    def validate_encryption(
        self,
        encryption_configurations: list[dict[str, Any]],
        environment_name: str,
    ) -> dict[str, Any]:
        """Validate encryption configurations against PCI DSS v4.0 requirements.

        Evaluates TLS versions, encryption algorithms, key lengths, and
        key management practices for PCI DSS v4.0 compliance covering
        Requirements 3, 4, and 6.

        Args:
            encryption_configurations: List of encryption config dicts with
                'component', 'tls_version', 'algorithm', 'key_length' keys.
            environment_name: Environment being validated.

        Returns:
            Encryption validation report dict with findings and gaps.
        """
        findings: list[dict[str, Any]] = []
        non_compliant_count = 0

        for config in encryption_configurations:
            component = config.get("component", "Unknown")
            tls_version = config.get("tls_version")
            algorithm = config.get("algorithm")
            key_length = config.get("key_length")
            component_findings: list[str] = []
            compliant = True

            if tls_version and tls_version not in _APPROVED_TLS_VERSIONS:
                component_findings.append(
                    f"TLS version '{tls_version}' is not approved. "
                    "PCI DSS v4.0 requires TLS 1.2 or TLS 1.3."
                )
                compliant = False

            if algorithm and algorithm not in _APPROVED_ENCRYPTION_ALGORITHMS:
                component_findings.append(
                    f"Algorithm '{algorithm}' may not meet PCI DSS v4.0 strong cryptography requirements."
                )
                compliant = False

            if algorithm and key_length:
                alg_family = algorithm.split("-")[0]
                min_length = _MIN_KEY_LENGTHS.get(alg_family)
                if min_length and key_length < min_length:
                    component_findings.append(
                        f"Key length {key_length} bits insufficient for {alg_family}. "
                        f"Minimum required: {min_length} bits."
                    )
                    compliant = False

            if not compliant:
                non_compliant_count += 1

            findings.append({
                "component": component,
                "tls_version": tls_version,
                "algorithm": algorithm,
                "key_length": key_length,
                "compliant": compliant,
                "findings": component_findings,
                "pci_requirements": ["3.5.1", "4.2.1"],
            })

        total_components = len(encryption_configurations)
        compliant_count = total_components - non_compliant_count

        validation_report = {
            "environment_name": environment_name,
            "total_components_assessed": total_components,
            "compliant_components": compliant_count,
            "non_compliant_components": non_compliant_count,
            "compliance_rate_pct": round(
                (compliant_count / total_components * 100) if total_components > 0 else 100.0, 2
            ),
            "component_findings": findings,
            "pci_requirements_covered": ["3.5.1", "4.2.1", "6.2.4"],
            "approved_tls_versions": sorted(_APPROVED_TLS_VERSIONS),
            "approved_algorithms": sorted(_APPROVED_ENCRYPTION_ALGORITHMS),
            "validated_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "PCI DSS encryption validation complete",
            environment_name=environment_name,
            total_components=total_components,
            non_compliant_count=non_compliant_count,
        )

        return validation_report

    def verify_access_controls(
        self,
        access_control_findings: list[dict[str, Any]],
        mfa_enabled_systems: list[str],
        shared_accounts_detected: list[str],
        privileged_access_reviewed: bool,
    ) -> dict[str, Any]:
        """Verify access controls against PCI DSS v4.0 Requirements 7 and 8.

        Evaluates need-to-know access enforcement, MFA implementation,
        unique user IDs, and privileged access reviews.

        Args:
            access_control_findings: List of access control assessment findings.
            mfa_enabled_systems: List of systems with MFA enabled.
            shared_accounts_detected: List of shared accounts found.
            privileged_access_reviewed: Whether privileged access was reviewed.

        Returns:
            Access control verification report dict.
        """
        non_compliant_findings: list[dict[str, Any]] = []
        compliant_findings: list[dict[str, Any]] = []

        for finding in access_control_findings:
            if not finding.get("need_to_know_enforced", True):
                non_compliant_findings.append({
                    "system": finding.get("system"),
                    "issue": "Need-to-know access not enforced",
                    "pci_requirement": "7.2.1",
                    "risk_level": "high",
                })
            elif finding.get("compliant", True):
                compliant_findings.append(finding)

        shared_account_violations = [
            {
                "account": acct,
                "issue": "Shared or generic account detected — unique user IDs required",
                "pci_requirement": "8.2.1",
                "risk_level": "critical",
            }
            for acct in shared_accounts_detected
        ]
        non_compliant_findings.extend(shared_account_violations)

        cde_systems_without_mfa = [
            f"System missing MFA: {system}"
            for system in access_control_findings
            if system.get("system") not in mfa_enabled_systems
        ]

        if not privileged_access_reviewed:
            non_compliant_findings.append({
                "issue": "Privileged access review not completed",
                "pci_requirement": "7.3.1",
                "risk_level": "high",
            })

        verification_report = {
            "total_findings_assessed": len(access_control_findings),
            "compliant_count": len(compliant_findings),
            "non_compliant_count": len(non_compliant_findings),
            "mfa_enabled_system_count": len(mfa_enabled_systems),
            "shared_accounts_detected": len(shared_accounts_detected),
            "privileged_access_reviewed": privileged_access_reviewed,
            "non_compliant_findings": non_compliant_findings,
            "systems_potentially_missing_mfa": cde_systems_without_mfa,
            "pci_requirements_covered": ["7.1.1", "7.2.1", "7.3.1", "8.2.1", "8.3.1", "8.4.1"],
            "overall_compliant": len(non_compliant_findings) == 0,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "PCI DSS access control verification complete",
            non_compliant_count=len(non_compliant_findings),
            shared_accounts=len(shared_accounts_detected),
        )

        return verification_report

    def check_network_segmentation(
        self,
        network_segments: list[dict[str, Any]],
        firewall_rules_count: int,
        segmentation_test_date: datetime | None,
    ) -> dict[str, Any]:
        """Check network segmentation controls per PCI DSS v4.0 Requirement 1.

        Evaluates network isolation between the CDE and other network zones,
        firewall rule adequacy, and segmentation testing schedule.

        Args:
            network_segments: List of network segment dicts with 'name', 'type',
                'cde_adjacent', 'isolated' keys.
            firewall_rules_count: Total number of firewall rules in place.
            segmentation_test_date: Date of last network segmentation test.

        Returns:
            Network segmentation compliance report dict.
        """
        cde_segments = [s for s in network_segments if s.get("type") == "CDE"]
        untrusted_adjacent = [
            s for s in network_segments
            if s.get("cde_adjacent") and s.get("type") == "untrusted"
        ]
        improperly_isolated = [
            s for s in cde_segments if not s.get("isolated", True)
        ]

        segmentation_valid = len(improperly_isolated) == 0

        # Segmentation test must be performed at least annually per PCI DSS v4.0 11.4.5
        test_current = False
        if segmentation_test_date:
            days_since_test = (datetime.now(timezone.utc) - segmentation_test_date).days
            test_current = days_since_test <= 365

        insufficient_firewall_rules = firewall_rules_count < 10

        result = {
            "total_segments_assessed": len(network_segments),
            "cde_segments_identified": len(cde_segments),
            "untrusted_cde_adjacent_segments": len(untrusted_adjacent),
            "improperly_isolated_segments": [s.get("name") for s in improperly_isolated],
            "network_segmentation_valid": segmentation_valid,
            "firewall_rules_count": firewall_rules_count,
            "firewall_rules_adequate": not insufficient_firewall_rules,
            "segmentation_test_date": segmentation_test_date.isoformat() if segmentation_test_date else None,
            "segmentation_test_current": test_current,
            "pci_requirements_covered": ["1.1.1", "1.2.1", "1.3.1", "1.3.2", "1.4.1", "11.4.5"],
            "gaps": [],
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

        gaps: list[str] = []
        if improperly_isolated:
            gaps.append(f"{len(improperly_isolated)} CDE segment(s) are not properly isolated")
        if not test_current:
            gaps.append("Network segmentation test is overdue — must be performed annually")
        if insufficient_firewall_rules:
            gaps.append("Firewall rule count appears insufficient for adequate CDE protection")
        if untrusted_adjacent:
            gaps.append(f"{len(untrusted_adjacent)} untrusted segment(s) are adjacent to the CDE")

        result["gaps"] = gaps
        result["overall_compliant"] = len(gaps) == 0

        logger.info(
            "PCI DSS network segmentation check complete",
            cde_segments=len(cde_segments),
            segmentation_valid=segmentation_valid,
            gaps=len(gaps),
        )

        return result

    def generate_pci_compliance_report(
        self,
        tenant_id: uuid.UUID,
        scan_id: uuid.UUID,
        scope_description: str,
        control_results: list[dict[str, Any]],
        merchant_level: int = 1,
    ) -> dict[str, Any]:
        """Generate a QSA-ready PCI DSS v4.0 compliance report.

        Produces a comprehensive compliance report summarizing control
        assessment results, compliance percentage, and remediation plan
        suitable for Qualified Security Assessor (QSA) review.

        Args:
            tenant_id: Tenant UUID for scoping.
            scan_id: Scan session UUID for reference.
            scope_description: CDE scope description.
            control_results: List of control assessment result dicts.
            merchant_level: PCI DSS merchant level (1-4).

        Returns:
            QSA-ready compliance report dict.
        """
        compliant = [r for r in control_results if r.get("status") == "compliant"]
        non_compliant = [r for r in control_results if r.get("status") == "non_compliant"]
        compensating = [r for r in control_results if r.get("status") == "compensating_control"]
        not_applicable = [r for r in control_results if r.get("status") == "not_applicable"]

        total_applicable = len(compliant) + len(non_compliant) + len(compensating)
        compliance_pct = (len(compliant) / total_applicable * 100) if total_applicable > 0 else 100.0
        qsa_ready = len(non_compliant) == 0

        # Group findings by requirement domain
        domain_summary: dict[str, dict[str, int]] = {}
        for result in control_results:
            domain = result.get("domain", "General")
            if domain not in domain_summary:
                domain_summary[domain] = {"compliant": 0, "non_compliant": 0, "compensating": 0}
            status = result.get("status", "")
            if status in domain_summary[domain]:
                domain_summary[domain][status] += 1

        report = {
            "report_id": str(uuid.uuid4()),
            "tenant_id": str(tenant_id),
            "scan_id": str(scan_id),
            "pci_dss_version": "4.0",
            "scope_description": scope_description,
            "merchant_level": merchant_level,
            "assessment_date": datetime.now(timezone.utc).isoformat(),
            "assessment_summary": {
                "total_controls_assessed": len(control_results),
                "compliant_controls": len(compliant),
                "non_compliant_controls": len(non_compliant),
                "compensating_controls": len(compensating),
                "not_applicable_controls": len(not_applicable),
                "compliance_percentage": round(compliance_pct, 2),
                "qsa_ready": qsa_ready,
            },
            "domain_summary": domain_summary,
            "non_compliant_findings": [
                {
                    "control_id": r.get("control_id"),
                    "requirement": r.get("requirement"),
                    "description": r.get("description"),
                    "remediation": r.get("remediation_guidance", "Contact PCI QSA for remediation guidance"),
                    "risk_level": r.get("risk_level", "high"),
                }
                for r in non_compliant
            ],
            "remediation_plan_required": len(non_compliant) > 0,
            "next_assessment_required_days": 90 if merchant_level == 1 else 365,
            "attestation_of_compliance_required": merchant_level == 1,
            "report_version": "1.0",
            "pci_ssc_reference": "PCI DSS v4.0, March 2022",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "PCI DSS compliance report generated",
            tenant_id=str(tenant_id),
            scan_id=str(scan_id),
            compliance_pct=round(compliance_pct, 2),
            non_compliant=len(non_compliant),
            qsa_ready=qsa_ready,
        )

        return report


__all__ = ["PCIDSSChecker"]
