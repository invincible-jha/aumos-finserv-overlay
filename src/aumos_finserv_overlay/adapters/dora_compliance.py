"""DORA (Digital Operational Resilience Act) compliance adapter for aumos-finserv-overlay.

Implements EU Regulation 2022/2554 ICT resilience requirements including
ICT risk management assessment, incident reporting, resilience testing
scheduling, third-party risk management, and DORA Article mapping.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# DORA Article structure mapping to requirements
_DORA_ARTICLES: dict[str, dict[str, Any]] = {
    "Article 5": {
        "title": "ICT governance and strategy",
        "pillar": "ICT Risk Management",
        "requirements": [
            "Board-level ICT risk oversight",
            "ICT risk management framework documented",
            "ICT strategy aligned with business strategy",
        ],
    },
    "Article 6": {
        "title": "ICT risk management framework",
        "pillar": "ICT Risk Management",
        "requirements": [
            "Comprehensive ICT risk management framework",
            "ICT risk appetite defined and approved",
            "ICT risk tolerance levels established",
        ],
    },
    "Article 7": {
        "title": "ICT systems, protocols and tools",
        "pillar": "ICT Risk Management",
        "requirements": [
            "ICT asset inventory maintained",
            "ICT systems classified by criticality",
            "Legacy system risk mitigated",
        ],
    },
    "Article 8": {
        "title": "Identification of ICT risk",
        "pillar": "ICT Risk Management",
        "requirements": [
            "ICT risk identification processes defined",
            "ICT risk assessment performed annually",
            "Third-party ICT concentrations identified",
        ],
    },
    "Article 9": {
        "title": "Protection and prevention",
        "pillar": "ICT Risk Management",
        "requirements": [
            "ICT access controls implemented",
            "Data classification and handling controls",
            "Network security controls implemented",
        ],
    },
    "Article 10": {
        "title": "Detection",
        "pillar": "ICT Risk Management",
        "requirements": [
            "Anomaly detection mechanisms deployed",
            "ICT incident detection procedures defined",
            "Monitoring and alerting capabilities established",
        ],
    },
    "Article 11": {
        "title": "Response and recovery",
        "pillar": "ICT Risk Management",
        "requirements": [
            "ICT business continuity policy established",
            "ICT disaster recovery plan documented",
            "RTO and RPO objectives defined and tested",
        ],
    },
    "Article 17": {
        "title": "Classification of ICT-related incidents",
        "pillar": "ICT Incident Reporting",
        "requirements": [
            "ICT incident classification criteria defined",
            "Major incident thresholds aligned with DORA",
            "Incident severity taxonomy implemented",
        ],
    },
    "Article 19": {
        "title": "Reporting of major ICT-related incidents",
        "pillar": "ICT Incident Reporting",
        "requirements": [
            "Initial notification to competent authority within 4 hours",
            "Intermediate report within 72 hours",
            "Final report within one month",
        ],
    },
    "Article 24": {
        "title": "General requirements for DORA testing",
        "pillar": "Digital Operational Resilience Testing",
        "requirements": [
            "ICT testing programme established",
            "Testing covers all critical ICT systems",
            "Testing performed at least annually",
        ],
    },
    "Article 26": {
        "title": "Threat-led penetration testing (TLPT)",
        "pillar": "Digital Operational Resilience Testing",
        "requirements": [
            "TLPT performed every three years for significant entities",
            "TLPT scope approved by competent authority",
            "TLPT findings remediated within agreed timeline",
        ],
    },
    "Article 28": {
        "title": "General principles for ICT third-party risk management",
        "pillar": "ICT Third-Party Risk",
        "requirements": [
            "ICT third-party risk policy established",
            "Pre-engagement due diligence performed",
            "Contractual provisions for ICT services defined",
        ],
    },
    "Article 30": {
        "title": "Key contractual provisions",
        "pillar": "ICT Third-Party Risk",
        "requirements": [
            "Contractual provisions include full service descriptions",
            "Sub-contracting arrangements disclosed",
            "Exit strategies and termination rights documented",
        ],
    },
    "Article 45": {
        "title": "Voluntary information sharing",
        "pillar": "Information Sharing",
        "requirements": [
            "Information sharing arrangements may be established",
            "Cyber threat intelligence shared with peers",
            "ISAC participation documented",
        ],
    },
}

# DORA pillar weighting for overall score
_PILLAR_WEIGHTS = {
    "ICT Risk Management": 0.35,
    "ICT Incident Reporting": 0.25,
    "Digital Operational Resilience Testing": 0.20,
    "ICT Third-Party Risk": 0.15,
    "Information Sharing": 0.05,
}

# Incident severity thresholds per DORA RTS definitions
_DORA_INCIDENT_THRESHOLDS = {
    "major_clients_threshold_pct": 0.10,
    "transaction_value_eur_threshold": 5_000_000,
    "duration_threshold_minutes": 120,
    "data_loss_records_threshold": 100_000,
    "geographies_threshold": 3,
}

# Resilience testing schedule requirements by entity type
_TESTING_SCHEDULE: dict[str, dict[str, Any]] = {
    "significant": {
        "basic_testing_years": 1,
        "tlpt_years": 3,
        "scenario_testing_years": 2,
    },
    "standard": {
        "basic_testing_years": 1,
        "tlpt_years": 5,
        "scenario_testing_years": 3,
    },
}


class DORAComplianceAdapter:
    """Evaluates EU DORA Digital Operational Resilience Act compliance.

    Provides comprehensive DORA Article-level assessment covering ICT risk
    management, incident reporting requirements, resilience testing scheduling,
    third-party ICT risk management, and information sharing protocols.
    """

    def __init__(self) -> None:
        """Initialize DORA compliance adapter."""
        pass

    def assess_ict_risk_management(
        self,
        ict_register_complete: bool,
        ict_risk_framework_documented: bool,
        ict_risk_appetite_approved: bool,
        asset_classification_done: bool,
        vulnerability_management_active: bool,
        third_party_concentrations_identified: bool,
        rto_hours: float | None,
        rpo_hours: float | None,
        rto_threshold_hours: float = 4.0,
        rpo_threshold_hours: float = 1.0,
    ) -> dict[str, Any]:
        """Assess ICT risk management posture per DORA Articles 5-11.

        Evaluates the five ICT risk management components and computes
        a pillar score representing compliance with DORA governance,
        identification, protection, detection, and response requirements.

        Args:
            ict_register_complete: Whether the ICT asset register is complete.
            ict_risk_framework_documented: Whether the ICT risk framework is documented.
            ict_risk_appetite_approved: Whether ICT risk appetite is board-approved.
            asset_classification_done: Whether ICT assets are classified by criticality.
            vulnerability_management_active: Whether vulnerability management is active.
            third_party_concentrations_identified: Whether ICT concentrations are identified.
            rto_hours: Current recovery time objective in hours.
            rpo_hours: Current recovery point objective in hours.
            rto_threshold_hours: Maximum acceptable RTO in hours.
            rpo_threshold_hours: Maximum acceptable RPO in hours.

        Returns:
            ICT risk management assessment dict with pillar score and gaps.
        """
        checks = {
            "ict_register_complete": ict_register_complete,
            "ict_risk_framework_documented": ict_risk_framework_documented,
            "ict_risk_appetite_approved": ict_risk_appetite_approved,
            "asset_classification_done": asset_classification_done,
            "vulnerability_management_active": vulnerability_management_active,
            "third_party_concentrations_identified": third_party_concentrations_identified,
        }

        rto_meets_threshold = rto_hours is not None and rto_hours <= rto_threshold_hours
        rpo_meets_threshold = rpo_hours is not None and rpo_hours <= rpo_threshold_hours
        checks["rto_meets_threshold"] = rto_meets_threshold
        checks["rpo_meets_threshold"] = rpo_meets_threshold

        passed_checks = sum(1 for v in checks.values() if v)
        total_checks = len(checks)
        pillar_score = round((passed_checks / total_checks) * 100, 2)

        gaps: list[str] = []
        article_coverage: dict[str, str] = {}

        if not ict_register_complete:
            gaps.append("ICT asset register not complete — required by DORA Article 7")
            article_coverage["Article 7"] = "Non-compliant"
        else:
            article_coverage["Article 7"] = "Compliant"

        if not ict_risk_framework_documented:
            gaps.append("ICT risk framework not documented — required by DORA Article 6")
            article_coverage["Article 6"] = "Non-compliant"
        else:
            article_coverage["Article 6"] = "Compliant"

        if not ict_risk_appetite_approved:
            gaps.append("ICT risk appetite not board-approved — required by DORA Article 5")
            article_coverage["Article 5"] = "Non-compliant"
        else:
            article_coverage["Article 5"] = "Compliant"

        if not rto_meets_threshold:
            gaps.append(
                f"RTO {rto_hours}h exceeds {rto_threshold_hours}h threshold — "
                "DORA Article 11 requires documented RTO/RPO objectives"
            )
        if not rpo_meets_threshold:
            gaps.append(
                f"RPO {rpo_hours}h exceeds {rpo_threshold_hours}h threshold — "
                "DORA Article 11 requires tested recovery capabilities"
            )

        article_coverage.setdefault("Article 11", "Compliant" if rto_meets_threshold and rpo_meets_threshold else "Partial")

        assessment = {
            "pillar": "ICT Risk Management",
            "pillar_score_pct": pillar_score,
            "checks_passed": passed_checks,
            "checks_total": total_checks,
            "check_results": checks,
            "rto_hours": rto_hours,
            "rpo_hours": rpo_hours,
            "rto_compliant": rto_meets_threshold,
            "rpo_compliant": rpo_meets_threshold,
            "article_coverage": article_coverage,
            "gaps": gaps,
            "assessed_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "DORA ICT risk management assessed",
            pillar_score=pillar_score,
            gaps_count=len(gaps),
        )

        return assessment

    def check_incident_reporting(
        self,
        incident_classification_defined: bool,
        reporting_procedures_documented: bool,
        initial_notification_tested: bool,
        intermediate_report_tested: bool,
        final_report_template_exists: bool,
        competent_authority_contact: str | None,
    ) -> dict[str, Any]:
        """Check DORA ICT incident reporting readiness per Articles 17-19.

        Evaluates incident classification capability, reporting timeline
        adherence (4h/72h/1 month), and competent authority notification
        procedures required by DORA.

        Args:
            incident_classification_defined: Whether major incident criteria are defined.
            reporting_procedures_documented: Whether reporting procedures are documented.
            initial_notification_tested: Whether 4-hour notification was tested.
            intermediate_report_tested: Whether 72-hour report process was tested.
            final_report_template_exists: Whether final report template exists.
            competent_authority_contact: Contact details for competent authority.

        Returns:
            Incident reporting compliance dict with timeline requirements.
        """
        requirements_met: dict[str, bool] = {
            "major_incident_classification_defined": incident_classification_defined,
            "reporting_procedures_documented": reporting_procedures_documented,
            "initial_notification_4h_tested": initial_notification_tested,
            "intermediate_report_72h_tested": intermediate_report_tested,
            "final_report_1_month_template": final_report_template_exists,
            "competent_authority_contact_known": competent_authority_contact is not None,
        }

        passed = sum(1 for v in requirements_met.values() if v)
        total = len(requirements_met)
        pillar_score = round((passed / total) * 100, 2)

        timeline_requirements = {
            "initial_notification": {
                "timeframe": "4 hours from major incident classification",
                "dora_article": "Article 19(1)",
                "met": initial_notification_tested,
            },
            "intermediate_report": {
                "timeframe": "72 hours from initial classification",
                "dora_article": "Article 19(3)",
                "met": intermediate_report_tested,
            },
            "final_report": {
                "timeframe": "1 month from intermediate report",
                "dora_article": "Article 19(5)",
                "met": final_report_template_exists,
            },
        }

        thresholds = {
            "major_clients_threshold_pct": _DORA_INCIDENT_THRESHOLDS["major_clients_threshold_pct"],
            "transaction_value_eur": _DORA_INCIDENT_THRESHOLDS["transaction_value_eur_threshold"],
            "duration_minutes": _DORA_INCIDENT_THRESHOLDS["duration_threshold_minutes"],
            "data_loss_records": _DORA_INCIDENT_THRESHOLDS["data_loss_records_threshold"],
            "geographies": _DORA_INCIDENT_THRESHOLDS["geographies_threshold"],
        }

        gaps = [key.replace("_", " ") for key, met in requirements_met.items() if not met]

        result = {
            "pillar": "ICT Incident Reporting",
            "pillar_score_pct": pillar_score,
            "requirements_met": requirements_met,
            "timeline_requirements": timeline_requirements,
            "major_incident_thresholds": thresholds,
            "competent_authority_contact": competent_authority_contact,
            "dora_articles_covered": ["Article 17", "Article 19"],
            "gaps": gaps,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "DORA incident reporting checked",
            pillar_score=pillar_score,
            gaps_count=len(gaps),
        )

        return result

    def schedule_resilience_testing(
        self,
        entity_type: str,
        last_basic_test_date: datetime | None,
        last_tlpt_date: datetime | None,
        last_scenario_test_date: datetime | None,
        critical_systems: list[str],
        tlpt_providers: list[str],
    ) -> dict[str, Any]:
        """Schedule DORA resilience testing programme per Articles 24-26.

        Calculates next required testing dates, identifies overdue tests,
        and generates a testing calendar aligned with DORA testing requirements
        for basic ICT testing and threat-led penetration testing (TLPT).

        Args:
            entity_type: Entity classification ('significant' or 'standard').
            last_basic_test_date: Date of last basic ICT resilience test.
            last_tlpt_date: Date of last threat-led penetration test.
            last_scenario_test_date: Date of last scenario-based test.
            critical_systems: List of critical ICT systems in scope.
            tlpt_providers: List of approved TLPT providers.

        Returns:
            Resilience testing schedule dict with calendar and overdue items.
        """
        entity_type = entity_type if entity_type in _TESTING_SCHEDULE else "standard"
        schedule_config = _TESTING_SCHEDULE[entity_type]
        now = datetime.now(timezone.utc)

        def next_test_date(last_date: datetime | None, frequency_years: int) -> datetime:
            if last_date is None:
                return now  # Overdue — schedule immediately
            return last_date + timedelta(days=frequency_years * 365)

        next_basic_test = next_test_date(last_basic_test_date, schedule_config["basic_testing_years"])
        next_tlpt = next_test_date(last_tlpt_date, schedule_config["tlpt_years"])
        next_scenario_test = next_test_date(last_scenario_test_date, schedule_config["scenario_testing_years"])

        overdue_tests: list[dict[str, Any]] = []
        if next_basic_test < now:
            overdue_tests.append({
                "test_type": "Basic ICT resilience testing",
                "dora_article": "Article 24",
                "overdue_since": next_basic_test.isoformat(),
            })
        if next_tlpt < now:
            overdue_tests.append({
                "test_type": "Threat-led penetration testing (TLPT)",
                "dora_article": "Article 26",
                "overdue_since": next_tlpt.isoformat(),
            })
        if next_scenario_test < now:
            overdue_tests.append({
                "test_type": "Scenario-based resilience testing",
                "dora_article": "Article 24",
                "overdue_since": next_scenario_test.isoformat(),
            })

        testing_calendar = [
            {
                "test_type": "Basic ICT resilience testing",
                "dora_article": "Article 24",
                "next_required": next_basic_test.isoformat(),
                "frequency_years": schedule_config["basic_testing_years"],
                "overdue": next_basic_test < now,
            },
            {
                "test_type": "Threat-led penetration testing (TLPT)",
                "dora_article": "Article 26",
                "next_required": next_tlpt.isoformat(),
                "frequency_years": schedule_config["tlpt_years"],
                "overdue": next_tlpt < now,
            },
            {
                "test_type": "Scenario-based resilience testing",
                "dora_article": "Article 24",
                "next_required": next_scenario_test.isoformat(),
                "frequency_years": schedule_config["scenario_testing_years"],
                "overdue": next_scenario_test < now,
            },
        ]

        result = {
            "entity_type": entity_type,
            "critical_systems_in_scope": critical_systems,
            "tlpt_providers": tlpt_providers,
            "testing_calendar": testing_calendar,
            "overdue_tests": overdue_tests,
            "overdue_count": len(overdue_tests),
            "next_immediate_action": overdue_tests[0]["test_type"] if overdue_tests else None,
            "dora_articles_covered": ["Article 24", "Article 25", "Article 26"],
            "scheduled_at": now.isoformat(),
        }

        logger.info(
            "DORA resilience testing scheduled",
            entity_type=entity_type,
            overdue_count=len(overdue_tests),
        )

        return result

    def assess_third_party_risk(
        self,
        ict_providers: list[dict[str, Any]],
        critical_functions_outsourced: list[str],
        concentration_risk_assessed: bool,
        exit_strategies_documented: bool,
    ) -> dict[str, Any]:
        """Assess ICT third-party risk management per DORA Articles 28-30.

        Evaluates the completeness of ICT third-party risk management
        including provider due diligence, contractual provisions, concentration
        risk assessment, and exit strategy documentation.

        Args:
            ict_providers: List of ICT provider dicts with 'name', 'critical',
                'due_diligence_complete', 'contract_compliant' keys.
            critical_functions_outsourced: List of critical ICT functions outsourced.
            concentration_risk_assessed: Whether ICT concentration risk is assessed.
            exit_strategies_documented: Whether exit strategies are documented.

        Returns:
            Third-party risk assessment dict with provider findings.
        """
        critical_providers = [p for p in ict_providers if p.get("critical", False)]
        providers_missing_due_diligence = [
            p for p in ict_providers if not p.get("due_diligence_complete", False)
        ]
        providers_missing_contract = [
            p for p in ict_providers if not p.get("contract_compliant", False)
        ]

        gaps: list[str] = []
        if providers_missing_due_diligence:
            gaps.append(
                f"{len(providers_missing_due_diligence)} ICT provider(s) missing due diligence — "
                "required by DORA Article 28"
            )
        if providers_missing_contract:
            gaps.append(
                f"{len(providers_missing_contract)} ICT provider(s) missing DORA-compliant contracts — "
                "required by DORA Article 30"
            )
        if not concentration_risk_assessed:
            gaps.append("ICT concentration risk not assessed — required by DORA Article 29")
        if not exit_strategies_documented:
            gaps.append("Exit strategies not documented — required by DORA Article 30")

        passed_checks = 4 - len([
            g for g in [
                not providers_missing_due_diligence,
                not providers_missing_contract,
                concentration_risk_assessed,
                exit_strategies_documented,
            ] if not g
        ])
        pillar_score = round((passed_checks / 4) * 100, 2)

        result = {
            "pillar": "ICT Third-Party Risk",
            "pillar_score_pct": pillar_score,
            "total_ict_providers": len(ict_providers),
            "critical_providers_count": len(critical_providers),
            "critical_functions_outsourced": critical_functions_outsourced,
            "providers_missing_due_diligence": [p.get("name") for p in providers_missing_due_diligence],
            "providers_missing_contract_compliance": [p.get("name") for p in providers_missing_contract],
            "concentration_risk_assessed": concentration_risk_assessed,
            "exit_strategies_documented": exit_strategies_documented,
            "dora_articles_covered": ["Article 28", "Article 29", "Article 30"],
            "gaps": gaps,
            "assessed_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "DORA third-party risk assessed",
            total_providers=len(ict_providers),
            critical_providers=len(critical_providers),
            gaps_count=len(gaps),
        )

        return result

    def analyze_compliance_gaps(
        self,
        ict_risk_management_score: float,
        incident_reporting_score: float,
        resilience_testing_score: float,
        third_party_risk_score: float,
        information_sharing_score: float,
    ) -> dict[str, Any]:
        """Analyze overall DORA compliance gaps across all five pillars.

        Computes weighted overall compliance score and generates prioritized
        remediation plan based on pillar scores and DORA regulatory timelines.

        Args:
            ict_risk_management_score: ICT risk management pillar score 0-100.
            incident_reporting_score: Incident reporting pillar score 0-100.
            resilience_testing_score: Resilience testing pillar score 0-100.
            third_party_risk_score: Third-party risk pillar score 0-100.
            information_sharing_score: Information sharing pillar score 0-100.

        Returns:
            DORA gap analysis dict with weighted scores and remediation priorities.
        """
        pillar_scores = {
            "ICT Risk Management": ict_risk_management_score,
            "ICT Incident Reporting": incident_reporting_score,
            "Digital Operational Resilience Testing": resilience_testing_score,
            "ICT Third-Party Risk": third_party_risk_score,
            "Information Sharing": information_sharing_score,
        }

        weighted_score = sum(
            score * _PILLAR_WEIGHTS[pillar]
            for pillar, score in pillar_scores.items()
        )

        # Identify critical gaps (pillars below 60%)
        critical_gaps = [
            {"pillar": pillar, "score": score, "priority": "CRITICAL"}
            for pillar, score in pillar_scores.items()
            if score < 60.0
        ]
        moderate_gaps = [
            {"pillar": pillar, "score": score, "priority": "MODERATE"}
            for pillar, score in pillar_scores.items()
            if 60.0 <= score < 80.0
        ]

        # Map gaps to DORA articles
        article_gaps: list[dict[str, Any]] = []
        for gap in critical_gaps + moderate_gaps:
            pillar = gap["pillar"]
            matching_articles = [
                article for article, info in _DORA_ARTICLES.items()
                if info["pillar"] == pillar
            ]
            for article in matching_articles:
                article_gaps.append({
                    "article": article,
                    "title": _DORA_ARTICLES[article]["title"],
                    "pillar": pillar,
                    "requirements": _DORA_ARTICLES[article]["requirements"],
                    "gap_priority": gap["priority"],
                })

        overall_compliant = weighted_score >= 80.0

        gap_analysis = {
            "overall_dora_score": round(weighted_score, 2),
            "overall_compliant": overall_compliant,
            "pillar_scores": pillar_scores,
            "pillar_weights": _PILLAR_WEIGHTS,
            "critical_gaps": critical_gaps,
            "moderate_gaps": moderate_gaps,
            "total_gaps": len(critical_gaps) + len(moderate_gaps),
            "article_gaps": article_gaps,
            "remediation_priorities": [
                {"pillar": g["pillar"], "score": g["score"], "priority": g["priority"]}
                for g in sorted(critical_gaps + moderate_gaps, key=lambda x: x["score"])
            ],
            "dora_effective_date": "2025-01-17",
            "regulatory_reference": "EU Regulation 2022/2554 — Digital Operational Resilience Act",
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "DORA compliance gap analysis complete",
            overall_score=round(weighted_score, 2),
            overall_compliant=overall_compliant,
            critical_gaps=len(critical_gaps),
        )

        return gap_analysis


__all__ = ["DORAComplianceAdapter"]
