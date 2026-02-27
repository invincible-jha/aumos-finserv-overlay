"""Anti-Money Laundering (AML) compliance checker adapter for aumos-finserv-overlay.

Implements FinCEN-aligned transaction pattern analysis, suspicious activity
detection, CTR/SAR trigger identification, customer risk scoring, sanctions
list screening simulation, and AML typology matching per FATF standards.
"""

import hashlib
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# FinCEN CTR threshold (Currency Transaction Report — required at $10,000+)
_CTR_THRESHOLD_USD = Decimal("10000.00")

# Structuring threshold — transactions slightly below CTR threshold
_STRUCTURING_UPPER_USD = Decimal("9999.99")
_STRUCTURING_LOWER_USD = Decimal("8500.00")

# SAR (Suspicious Activity Report) trigger patterns
_SAR_PATTERNS: dict[str, dict[str, Any]] = {
    "structuring": {
        "description": "Multiple transactions structured to evade CTR reporting",
        "minimum_transactions": 3,
        "time_window_hours": 24,
        "requires_ctr": False,
        "requires_sar": True,
        "fatf_typology": "FATF Typology 1 — Structuring",
        "risk_weight": 0.85,
    },
    "rapid_movement": {
        "description": "Funds moved rapidly between accounts with little economic purpose",
        "minimum_transactions": 2,
        "time_window_hours": 2,
        "requires_ctr": False,
        "requires_sar": True,
        "fatf_typology": "FATF Typology 2 — Layering",
        "risk_weight": 0.75,
    },
    "high_volume_cash": {
        "description": "Unusually high volume of cash transactions inconsistent with business profile",
        "minimum_transactions": 5,
        "time_window_hours": 168,
        "requires_ctr": True,
        "requires_sar": True,
        "fatf_typology": "FATF Typology 3 — Placement",
        "risk_weight": 0.80,
    },
    "third_party_payors": {
        "description": "Third parties making payments on behalf of customer",
        "minimum_transactions": 1,
        "time_window_hours": 720,
        "requires_ctr": False,
        "requires_sar": True,
        "fatf_typology": "FATF Typology 7 — Third-Party Payments",
        "risk_weight": 0.60,
    },
    "geographic_anomaly": {
        "description": "Transactions from high-risk jurisdictions",
        "minimum_transactions": 1,
        "time_window_hours": None,
        "requires_ctr": False,
        "requires_sar": True,
        "fatf_typology": "FATF Typology 9 — Geographic Anomaly",
        "risk_weight": 0.70,
    },
    "dormant_account_activity": {
        "description": "Sudden activity in previously dormant account",
        "minimum_transactions": 1,
        "time_window_hours": None,
        "requires_ctr": False,
        "requires_sar": True,
        "fatf_typology": "FATF Typology 6 — Dormant Account Reactivation",
        "risk_weight": 0.65,
    },
    "round_dollar_amounts": {
        "description": "Frequent round-dollar transactions often associated with money laundering",
        "minimum_transactions": 3,
        "time_window_hours": 168,
        "requires_ctr": False,
        "requires_sar": False,
        "fatf_typology": "FATF Typology 4 — Round Dollar Transactions",
        "risk_weight": 0.40,
    },
}

# FATF high-risk jurisdiction codes (illustrative — not exhaustive)
_HIGH_RISK_JURISDICTIONS = {
    "AF", "BY", "CF", "CD", "CU", "ET", "IR", "IQ", "LY", "ML",
    "MM", "KP", "RU", "SO", "SD", "SS", "SY", "UA", "YE", "ZW",
}

# Customer risk factors and weights for CDD risk scoring
_CUSTOMER_RISK_FACTORS: dict[str, float] = {
    "pep": 0.30,              # Politically Exposed Person
    "high_risk_jurisdiction": 0.25,
    "cash_intensive_business": 0.20,
    "adverse_media": 0.15,
    "unusual_transaction_profile": 0.10,
}

# AML program pillars per FinCEN BSA requirements
_AML_PROGRAM_PILLARS = [
    "Internal policies, procedures, and controls",
    "Designated compliance officer",
    "Ongoing training for staff",
    "Independent testing (audit)",
    "Customer identification program (CIP)",
    "Customer due diligence (CDD)",
    "Beneficial ownership identification",
    "Suspicious activity monitoring and reporting",
    "Currency transaction reporting",
]


class AMLChecker:
    """Performs anti-money laundering transaction analysis and compliance checks.

    Implements FinCEN BSA-aligned suspicious activity detection, CTR/SAR
    trigger identification, customer risk scoring, sanctions screening
    simulation, and comprehensive AML compliance reporting per FATF
    and FinCEN guidance.
    """

    def __init__(self) -> None:
        """Initialize AML checker."""
        pass

    def analyze_transaction_patterns(
        self,
        customer_id: str,
        transactions: list[dict[str, Any]],
        customer_profile: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Analyze transaction patterns for AML red flag indicators.

        Examines transaction history for structuring, layering, placement,
        and integration patterns consistent with FATF money laundering
        typologies and FinCEN suspicious activity guidance.

        Args:
            customer_id: Customer identifier.
            transactions: List of transaction dicts with 'amount', 'timestamp',
                'currency', 'counterparty', 'channel', 'country' keys.
            customer_profile: Optional customer profile dict for context.

        Returns:
            Transaction pattern analysis dict with detected patterns and risk score.
        """
        detected_patterns: list[dict[str, Any]] = []
        alerts: list[dict[str, Any]] = []

        # Check for structuring patterns
        structuring_alerts = self._check_structuring(transactions)
        if structuring_alerts:
            detected_patterns.extend(structuring_alerts)
            alerts.extend([
                {"alert_type": "STRUCTURING", "severity": "HIGH", "detail": a["description"]}
                for a in structuring_alerts
            ])

        # Check for rapid movement (layering)
        layering_alerts = self._check_rapid_movement(transactions)
        if layering_alerts:
            detected_patterns.extend(layering_alerts)
            alerts.extend([
                {"alert_type": "LAYERING", "severity": "HIGH", "detail": a["description"]}
                for a in layering_alerts
            ])

        # Check for high-risk jurisdiction exposure
        geo_alerts = self._check_geographic_risk(transactions)
        if geo_alerts:
            detected_patterns.extend(geo_alerts)
            alerts.extend([
                {"alert_type": "GEOGRAPHIC_RISK", "severity": "MEDIUM", "detail": a["description"]}
                for a in geo_alerts
            ])

        # Check for round-dollar patterns
        round_dollar_alerts = self._check_round_dollar(transactions)
        if round_dollar_alerts:
            detected_patterns.extend(round_dollar_alerts)

        # Compute overall risk score
        risk_score = sum(
            _SAR_PATTERNS.get(p.get("typology", ""), {}).get("risk_weight", 0.5)
            for p in detected_patterns
        )
        risk_score = min(1.0, risk_score)

        ctr_required = any(
            Decimal(str(tx.get("amount", 0))) >= _CTR_THRESHOLD_USD
            for tx in transactions
        )
        sar_required = len([p for p in detected_patterns if _SAR_PATTERNS.get(p.get("typology", ""), {}).get("requires_sar", False)]) > 0

        result = {
            "analysis_id": str(uuid.uuid4()),
            "customer_id": customer_id,
            "transactions_analyzed": len(transactions),
            "detected_patterns": detected_patterns,
            "alerts": alerts,
            "alert_count": len(alerts),
            "risk_score": round(risk_score, 4),
            "risk_level": self._classify_risk(risk_score),
            "ctr_required": ctr_required,
            "sar_required": sar_required,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "regulatory_framework": "FinCEN BSA / FATF Recommendations",
        }

        logger.info(
            "AML transaction pattern analysis complete",
            customer_id=customer_id,
            transactions_analyzed=len(transactions),
            risk_score=round(risk_score, 4),
            sar_required=sar_required,
            ctr_required=ctr_required,
        )

        return result

    def _check_structuring(
        self,
        transactions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Detect structuring patterns (smurfing).

        Args:
            transactions: Transaction list.

        Returns:
            List of detected structuring pattern dicts.
        """
        structuring_txs = [
            tx for tx in transactions
            if _STRUCTURING_LOWER_USD <= Decimal(str(tx.get("amount", 0))) <= _STRUCTURING_UPPER_USD
        ]

        if len(structuring_txs) >= _SAR_PATTERNS["structuring"]["minimum_transactions"]:
            total = sum(Decimal(str(tx.get("amount", 0))) for tx in structuring_txs)
            return [{
                "typology": "structuring",
                "pattern_name": "Transaction Structuring",
                "description": (
                    f"Detected {len(structuring_txs)} transactions between "
                    f"${float(_STRUCTURING_LOWER_USD):,.2f} and "
                    f"${float(_STRUCTURING_UPPER_USD):,.2f} — possible CTR evasion. "
                    f"Aggregate: ${float(total):,.2f}"
                ),
                "transaction_count": len(structuring_txs),
                "aggregate_amount": float(total),
                "fatf_typology": _SAR_PATTERNS["structuring"]["fatf_typology"],
                "sar_trigger": True,
            }]
        return []

    def _check_rapid_movement(
        self,
        transactions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Detect rapid fund movement (layering).

        Args:
            transactions: Transaction list.

        Returns:
            List of detected rapid movement pattern dicts.
        """
        if len(transactions) < 2:
            return []

        high_value_txs = [
            tx for tx in transactions
            if Decimal(str(tx.get("amount", 0))) >= Decimal("5000")
        ]

        if len(high_value_txs) >= 2:
            return [{
                "typology": "rapid_movement",
                "pattern_name": "Rapid Fund Movement",
                "description": (
                    f"{len(high_value_txs)} high-value transactions detected — "
                    "consistent with layering activity"
                ),
                "transaction_count": len(high_value_txs),
                "fatf_typology": _SAR_PATTERNS["rapid_movement"]["fatf_typology"],
                "sar_trigger": True,
            }]
        return []

    def _check_geographic_risk(
        self,
        transactions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Detect high-risk jurisdiction exposure.

        Args:
            transactions: Transaction list.

        Returns:
            List of detected geographic risk pattern dicts.
        """
        high_risk_txs = [
            tx for tx in transactions
            if tx.get("country", "US") in _HIGH_RISK_JURISDICTIONS
        ]

        if high_risk_txs:
            countries = list({tx.get("country") for tx in high_risk_txs})
            return [{
                "typology": "geographic_anomaly",
                "pattern_name": "High-Risk Jurisdiction Exposure",
                "description": (
                    f"Transactions from FATF high-risk jurisdictions: {', '.join(countries)}"
                ),
                "transaction_count": len(high_risk_txs),
                "high_risk_countries": countries,
                "fatf_typology": _SAR_PATTERNS["geographic_anomaly"]["fatf_typology"],
                "sar_trigger": True,
            }]
        return []

    def _check_round_dollar(
        self,
        transactions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Detect round-dollar transaction patterns.

        Args:
            transactions: Transaction list.

        Returns:
            List of round-dollar pattern dicts.
        """
        round_txs = [
            tx for tx in transactions
            if Decimal(str(tx.get("amount", 0))) % 1000 == 0
            and Decimal(str(tx.get("amount", 0))) >= Decimal("1000")
        ]

        if len(round_txs) >= _SAR_PATTERNS["round_dollar_amounts"]["minimum_transactions"]:
            return [{
                "typology": "round_dollar_amounts",
                "pattern_name": "Round-Dollar Transaction Pattern",
                "description": (
                    f"{len(round_txs)} round-dollar transactions detected — "
                    "may warrant enhanced due diligence"
                ),
                "transaction_count": len(round_txs),
                "fatf_typology": _SAR_PATTERNS["round_dollar_amounts"]["fatf_typology"],
                "sar_trigger": False,
            }]
        return []

    def _classify_risk(self, risk_score: float) -> str:
        """Classify AML risk level from score.

        Args:
            risk_score: Numeric risk score 0.0–1.0.

        Returns:
            Risk level string: HIGH, MEDIUM, or LOW.
        """
        if risk_score >= 0.70:
            return "HIGH"
        if risk_score >= 0.40:
            return "MEDIUM"
        return "LOW"

    def score_customer_risk(
        self,
        customer_id: str,
        is_pep: bool,
        country_of_residence: str,
        business_type: str,
        adverse_media_hits: int,
        transaction_volume_anomaly_score: float,
        account_age_days: int,
    ) -> dict[str, Any]:
        """Compute CDD customer risk score per FinCEN CDD Rule.

        Evaluates customer due diligence risk factors including PEP status,
        jurisdiction risk, business type, adverse media, and transaction
        behavior to produce a composite risk score and EDD determination.

        Args:
            customer_id: Customer identifier.
            is_pep: Whether customer is a Politically Exposed Person.
            country_of_residence: ISO 3166-1 alpha-2 country code.
            business_type: Customer's business type category.
            adverse_media_hits: Count of adverse media mentions.
            transaction_volume_anomaly_score: Anomaly score for transaction volume (0–1).
            account_age_days: Age of the account in days.

        Returns:
            Customer risk scoring dict with EDD determination.
        """
        risk_components: dict[str, float] = {}

        risk_components["pep_risk"] = _CUSTOMER_RISK_FACTORS["pep"] if is_pep else 0.0
        risk_components["jurisdiction_risk"] = (
            _CUSTOMER_RISK_FACTORS["high_risk_jurisdiction"]
            if country_of_residence in _HIGH_RISK_JURISDICTIONS
            else 0.0
        )

        cash_intensive_businesses = {"cash_advance", "money_services", "casino", "car_wash", "laundromat"}
        risk_components["business_type_risk"] = (
            _CUSTOMER_RISK_FACTORS["cash_intensive_business"]
            if business_type.lower() in cash_intensive_businesses
            else 0.0
        )

        risk_components["adverse_media_risk"] = min(
            _CUSTOMER_RISK_FACTORS["adverse_media"],
            adverse_media_hits * 0.05,
        )
        risk_components["transaction_anomaly_risk"] = (
            transaction_volume_anomaly_score * _CUSTOMER_RISK_FACTORS["unusual_transaction_profile"]
        )

        composite_score = sum(risk_components.values())
        composite_score = min(1.0, composite_score)

        risk_level = self._classify_risk(composite_score)
        edd_required = risk_level == "HIGH" or is_pep
        account_new = account_age_days < 90
        monitoring_frequency = "monthly" if risk_level == "HIGH" else "quarterly" if risk_level == "MEDIUM" else "annual"

        result = {
            "customer_id": customer_id,
            "composite_risk_score": round(composite_score, 4),
            "risk_level": risk_level,
            "risk_components": {k: round(v, 4) for k, v in risk_components.items()},
            "is_pep": is_pep,
            "country_of_residence": country_of_residence,
            "high_risk_jurisdiction": country_of_residence in _HIGH_RISK_JURISDICTIONS,
            "business_type": business_type,
            "adverse_media_hits": adverse_media_hits,
            "account_age_days": account_age_days,
            "account_new": account_new,
            "edd_required": edd_required,
            "monitoring_frequency": monitoring_frequency,
            "cdd_rule_reference": "FinCEN CDD Rule (31 CFR § 1010.230)",
            "scored_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "AML customer risk scored",
            customer_id=customer_id,
            composite_score=round(composite_score, 4),
            risk_level=risk_level,
            edd_required=edd_required,
        )

        return result

    def screen_sanctions(
        self,
        entity_name: str,
        entity_type: str,
        country: str,
        identifiers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Screen an entity against sanctions list indicators.

        Simulates OFAC SDN, EU consolidated list, and UN sanctions list
        screening using deterministic pattern matching on entity name and
        country. In production, this would integrate with live sanctions feeds.

        Args:
            entity_name: Full legal name of the entity.
            entity_type: Type of entity (individual/corporation/vessel/aircraft).
            country: ISO 3166-1 alpha-2 country code.
            identifiers: Optional dict of identifying numbers (passport, EIN, etc.).

        Returns:
            Sanctions screening result dict with match status and references.
        """
        # Deterministic simulation: flag high-risk country entities and
        # names containing known sanction-trigger test patterns
        name_hash = hashlib.sha256(entity_name.lower().encode()).hexdigest()
        country_risk = country in _HIGH_RISK_JURISDICTIONS

        # Simulate a fuzzy match (deterministic for testing — based on name hash)
        simulated_match_score = int(name_hash[:2], 16) / 255.0
        potential_hit = country_risk and simulated_match_score > 0.70

        result = {
            "screening_id": str(uuid.uuid4()),
            "entity_name": entity_name,
            "entity_type": entity_type,
            "country": country,
            "high_risk_jurisdiction": country_risk,
            "ofac_sdn_hit": potential_hit,
            "eu_consolidated_list_hit": potential_hit,
            "un_sanctions_hit": country_risk and simulated_match_score > 0.85,
            "match_score": round(simulated_match_score, 4),
            "potential_hit": potential_hit,
            "requires_manual_review": potential_hit,
            "regulatory_hold_recommended": potential_hit,
            "screening_lists_checked": [
                "OFAC SDN List",
                "OFAC Consolidated Sanctions List",
                "EU Consolidated List",
                "UN Security Council Sanctions",
            ],
            "screening_date": datetime.now(timezone.utc).isoformat(),
            "note": "Simulation mode — integrate with live OFAC/EU/UN feeds in production",
        }

        logger.info(
            "AML sanctions screening complete",
            entity_name=entity_name[:20] + "...",
            country=country,
            potential_hit=potential_hit,
            match_score=round(simulated_match_score, 4),
        )

        return result

    def generate_aml_compliance_report(
        self,
        tenant_id: uuid.UUID,
        reporting_period_start: datetime,
        reporting_period_end: datetime,
        high_risk_customers: int,
        medium_risk_customers: int,
        low_risk_customers: int,
        sars_filed: int,
        ctrs_filed: int,
        sanctions_hits: int,
        aml_program_elements_met: list[str],
    ) -> dict[str, Any]:
        """Generate a comprehensive AML compliance program report.

        Produces a FinCEN BSA-aligned compliance report summarizing customer
        risk distribution, SAR/CTR filing activity, sanctions screening results,
        and AML program element completeness.

        Args:
            tenant_id: Tenant UUID for scoping.
            reporting_period_start: Start of the reporting period.
            reporting_period_end: End of the reporting period.
            high_risk_customers: Count of high-risk customers.
            medium_risk_customers: Count of medium-risk customers.
            low_risk_customers: Count of low-risk customers.
            sars_filed: Number of SARs filed during the period.
            ctrs_filed: Number of CTRs filed during the period.
            sanctions_hits: Number of potential sanctions matches.
            aml_program_elements_met: List of AML program pillars implemented.

        Returns:
            AML compliance report dict with program assessment.
        """
        total_customers = high_risk_customers + medium_risk_customers + low_risk_customers
        high_risk_pct = (high_risk_customers / total_customers * 100) if total_customers > 0 else 0.0

        program_gaps = [
            pillar for pillar in _AML_PROGRAM_PILLARS
            if pillar not in aml_program_elements_met
        ]
        program_completeness = len(aml_program_elements_met) / len(_AML_PROGRAM_PILLARS) * 100

        report = {
            "report_id": str(uuid.uuid4()),
            "tenant_id": str(tenant_id),
            "reporting_period_start": reporting_period_start.isoformat(),
            "reporting_period_end": reporting_period_end.isoformat(),
            "customer_risk_summary": {
                "total_customers": total_customers,
                "high_risk": high_risk_customers,
                "medium_risk": medium_risk_customers,
                "low_risk": low_risk_customers,
                "high_risk_percentage": round(high_risk_pct, 2),
            },
            "filing_activity": {
                "sars_filed": sars_filed,
                "ctrs_filed": ctrs_filed,
                "sanctions_hits_reviewed": sanctions_hits,
                "sar_rate_per_1000_customers": round(
                    sars_filed / total_customers * 1000, 2
                ) if total_customers > 0 else 0.0,
            },
            "aml_program_assessment": {
                "program_pillars_required": len(_AML_PROGRAM_PILLARS),
                "program_pillars_implemented": len(aml_program_elements_met),
                "program_completeness_pct": round(program_completeness, 2),
                "program_gaps": program_gaps,
                "program_adequate": len(program_gaps) == 0,
            },
            "regulatory_framework": "FinCEN BSA / 31 CFR Chapter X",
            "bsa_officer_certification_required": True,
            "next_independent_review_due": (
                reporting_period_end + timedelta(days=365)
            ).isoformat(),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        from datetime import timedelta

        logger.info(
            "AML compliance report generated",
            tenant_id=str(tenant_id),
            total_customers=total_customers,
            sars_filed=sars_filed,
            program_completeness=round(program_completeness, 2),
        )

        return report

    def match_typologies(
        self,
        transaction_patterns: list[dict[str, Any]],
        customer_risk_level: str,
    ) -> dict[str, Any]:
        """Match detected transaction patterns to FATF AML typologies.

        Maps observed transaction patterns to the FATF money laundering
        typology library, providing regulatory-aligned classification for
        SAR narratives and examination preparation.

        Args:
            transaction_patterns: List of detected pattern dicts with 'typology' key.
            customer_risk_level: Customer's AML risk level (HIGH/MEDIUM/LOW).

        Returns:
            Typology matching result dict with FATF references.
        """
        matched_typologies: list[dict[str, Any]] = []
        sar_required_typologies: list[str] = []
        ctr_required_typologies: list[str] = []

        for pattern in transaction_patterns:
            typology_key = pattern.get("typology", "")
            typology_config = _SAR_PATTERNS.get(typology_key)
            if typology_config:
                matched_typologies.append({
                    "detected_pattern": pattern.get("pattern_name", typology_key),
                    "fatf_typology": typology_config["fatf_typology"],
                    "description": typology_config["description"],
                    "sar_trigger": typology_config["requires_sar"],
                    "ctr_trigger": typology_config["requires_ctr"],
                    "risk_weight": typology_config["risk_weight"],
                })
                if typology_config["requires_sar"]:
                    sar_required_typologies.append(typology_key)
                if typology_config["requires_ctr"]:
                    ctr_required_typologies.append(typology_key)

        sar_urgency = "immediate" if customer_risk_level == "HIGH" and sar_required_typologies else "standard"
        sar_deadline_days = 30 if sar_urgency == "immediate" else 60

        result = {
            "patterns_matched": len(matched_typologies),
            "matched_typologies": matched_typologies,
            "sar_required": len(sar_required_typologies) > 0,
            "ctr_required": len(ctr_required_typologies) > 0,
            "sar_urgency": sar_urgency,
            "sar_deadline_days": sar_deadline_days,
            "customer_risk_level": customer_risk_level,
            "regulatory_reference": "FATF 40 Recommendations / FinCEN SAR Rule (31 CFR § 1020.320)",
            "matched_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "AML typology matching complete",
            patterns_matched=len(matched_typologies),
            sar_required=result["sar_required"],
        )

        return result


__all__ = ["AMLChecker"]
