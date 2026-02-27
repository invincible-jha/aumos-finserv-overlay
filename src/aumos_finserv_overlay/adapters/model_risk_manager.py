"""SR 11-7 Model Risk Management adapter for aumos-finserv-overlay.

Implements Federal Reserve SR 11-7 / OCC 2011-12 model risk management
framework: model inventory management, risk tier classification, validation
requirement mapping, performance monitoring, and MRM report generation.
"""

import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# SR 11-7 model type classifications
_MODEL_TYPES = {
    "credit_scoring": "Credit Risk",
    "fraud_detection": "Operational Risk",
    "market_risk": "Market Risk",
    "liquidity_risk": "Liquidity Risk",
    "stress_testing": "Capital Planning",
    "pricing": "Market Risk",
    "behavioral": "Credit Risk",
    "aml_detection": "Compliance Risk",
    "regulatory_capital": "Capital Planning",
    "customer_lifetime_value": "Business Strategy",
    "nlp_classification": "Operational Risk",
    "generative_ai": "Operational Risk",
}

# Validation frequency requirements by risk tier (days between validations)
_VALIDATION_FREQUENCY: dict[str, int] = {
    "CRITICAL": 180,
    "HIGH": 365,
    "MEDIUM": 730,
    "LOW": 1095,
}

# SR 11-7 documentation requirements by tier
_DOCUMENTATION_REQUIREMENTS: dict[str, list[str]] = {
    "CRITICAL": [
        "Model development document (MDD)",
        "Independent validation report",
        "Model risk committee approval",
        "Production deployment attestation",
        "Ongoing monitoring plan",
        "Compensating controls documentation",
        "Model limitation inventory",
        "Challenger model comparison",
        "Performance benchmarks",
        "Regulatory capital impact analysis",
    ],
    "HIGH": [
        "Model development document (MDD)",
        "Independent validation report",
        "Ongoing monitoring plan",
        "Model limitation inventory",
        "Challenger model comparison",
        "Performance benchmarks",
    ],
    "MEDIUM": [
        "Model development document (MDD)",
        "Validation report (internal or independent)",
        "Ongoing monitoring plan",
        "Model limitation inventory",
    ],
    "LOW": [
        "Model development document (MDD)",
        "Validation report (internal)",
        "Ongoing monitoring plan",
    ],
}

# Performance monitoring metrics by model type
_MONITORING_METRICS: dict[str, list[str]] = {
    "credit_scoring": ["Gini coefficient", "KS statistic", "PSI", "default rate deviation"],
    "fraud_detection": ["Precision", "Recall", "F1-score", "False positive rate"],
    "market_risk": ["VaR backtesting p-value", "ES breach rate", "P&L attribution"],
    "stress_testing": ["Scenario coverage", "Capital adequacy ratio", "Loss estimation error"],
    "pricing": ["Model error rate", "Bid-ask spread accuracy", "Replication error"],
    "aml_detection": ["SAR filing rate", "True positive rate", "Alert precision"],
    "generative_ai": ["Hallucination rate", "Output relevance score", "Toxicity rate", "Drift score"],
}


class ModelRiskManager:
    """Manages SR 11-7 model risk framework compliance.

    Provides comprehensive model inventory management, risk tier classification,
    validation scheduling, challenger model comparison, and MRM reporting
    aligned with Federal Reserve SR 11-7 and OCC 2011-12 guidance.
    """

    def __init__(self) -> None:
        """Initialize model risk manager."""
        self._model_inventory: dict[str, dict[str, Any]] = {}

    def register_model(
        self,
        model_id: str,
        model_name: str,
        model_version: str,
        model_type: str,
        business_line: str,
        development_team: str,
        deployment_date: datetime,
        estimated_annual_exposure: Decimal,
        regulatory_capital_impact: bool,
        customer_facing: bool,
        production_systems: list[str],
        known_limitations: list[str],
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Register a model in the SR 11-7 model inventory.

        Creates a comprehensive model record with risk classification,
        documentation requirements, and monitoring schedule in the
        model risk inventory.

        Args:
            model_id: Unique model identifier.
            model_name: Human-readable model name.
            model_version: Semantic version string.
            model_type: Model type classification.
            business_line: Business line owning the model.
            development_team: Team responsible for model development.
            deployment_date: Date model was deployed to production.
            estimated_annual_exposure: Estimated annual financial exposure.
            regulatory_capital_impact: Whether model impacts regulatory capital.
            customer_facing: Whether model output is customer-facing.
            production_systems: List of production system names using the model.
            known_limitations: List of known model limitations.
            metadata: Optional additional metadata.

        Returns:
            Model inventory record dict with risk classification.
        """
        risk_category = _MODEL_TYPES.get(model_type, "Operational Risk")
        days_in_production = (datetime.now(timezone.utc) - deployment_date).days

        # Compute initial risk score
        exposure_score = self._score_exposure(float(estimated_annual_exposure))
        risk_score = (
            exposure_score * 0.40
            + (0.25 if regulatory_capital_impact else 0.0)
            + (0.20 if customer_facing else 0.0)
            + min(len(known_limitations) * 0.03, 0.15)
        )
        risk_tier = self._classify_tier(Decimal(str(risk_score)))

        docs_required = _DOCUMENTATION_REQUIREMENTS.get(risk_tier, _DOCUMENTATION_REQUIREMENTS["LOW"])
        next_validation = datetime.now(timezone.utc) + timedelta(
            days=_VALIDATION_FREQUENCY.get(risk_tier, 1095)
        )
        monitoring_metrics = _MONITORING_METRICS.get(model_type, ["Performance drift", "Error rate"])

        model_record = {
            "model_id": model_id,
            "model_name": model_name,
            "model_version": model_version,
            "model_type": model_type,
            "risk_category": risk_category,
            "business_line": business_line,
            "development_team": development_team,
            "deployment_date": deployment_date.isoformat(),
            "days_in_production": days_in_production,
            "estimated_annual_exposure": str(estimated_annual_exposure),
            "regulatory_capital_impact": regulatory_capital_impact,
            "customer_facing": customer_facing,
            "production_systems": production_systems,
            "known_limitations": known_limitations,
            "risk_score": round(risk_score, 4),
            "risk_tier": risk_tier,
            "validation_status": "PENDING_INITIAL_VALIDATION",
            "next_validation_date": next_validation.isoformat(),
            "validation_frequency_days": _VALIDATION_FREQUENCY.get(risk_tier, 1095),
            "documentation_required": docs_required,
            "monitoring_metrics": monitoring_metrics,
            "inventory_registered_at": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata or {},
        }

        self._model_inventory[model_id] = model_record

        logger.info(
            "Model registered in SR 11-7 inventory",
            model_id=model_id,
            model_name=model_name,
            risk_tier=risk_tier,
            risk_score=round(risk_score, 4),
        )

        return model_record

    def _score_exposure(self, exposure: float) -> float:
        """Score financial exposure on 0.0–1.0 scale.

        Args:
            exposure: Estimated annual financial exposure in dollars.

        Returns:
            Normalized exposure score.
        """
        if exposure >= 1_000_000_000:
            return 1.0
        if exposure >= 100_000_000:
            return 0.75
        if exposure >= 10_000_000:
            return 0.50
        if exposure >= 1_000_000:
            return 0.25
        return 0.10

    def _classify_tier(self, risk_score: Decimal) -> str:
        """Classify model into SR 11-7 risk tier.

        Args:
            risk_score: Composite risk score 0.0–1.0.

        Returns:
            Risk tier string: CRITICAL, HIGH, MEDIUM, or LOW.
        """
        if risk_score >= Decimal("0.85"):
            return "CRITICAL"
        if risk_score >= Decimal("0.65"):
            return "HIGH"
        if risk_score >= Decimal("0.40"):
            return "MEDIUM"
        return "LOW"

    def map_validation_requirements(
        self,
        model_id: str,
        risk_tier: str,
        regulatory_capital_impact: bool,
        customer_facing: bool,
        model_age_days: int,
    ) -> dict[str, Any]:
        """Map SR 11-7 validation requirements for a model.

        Generates detailed validation requirement specification based on
        risk tier, regulatory impact, customer-facing status, and model
        age per Federal Reserve SR 11-7 guidance.

        Args:
            model_id: Model identifier.
            risk_tier: SR 11-7 risk tier (CRITICAL/HIGH/MEDIUM/LOW).
            regulatory_capital_impact: Whether model impacts regulatory capital.
            customer_facing: Whether model output is customer-facing.
            model_age_days: Days since model was deployed to production.

        Returns:
            Validation requirements dict with scope and timeline.
        """
        independent_validation_required = risk_tier in ("CRITICAL", "HIGH") or regulatory_capital_impact
        validation_scope: list[str] = ["Conceptual soundness review", "Outcome analysis"]

        if risk_tier in ("CRITICAL", "HIGH"):
            validation_scope.extend([
                "Data integrity and quality assessment",
                "Process verification and replication",
                "Sensitivity analysis",
                "Benchmarking against challenger models",
                "Ongoing monitoring review",
            ])

        if regulatory_capital_impact:
            validation_scope.append("Regulatory capital calculation review")

        if customer_facing:
            validation_scope.append("ECOA/Regulation B adverse action notice review")

        if model_age_days > 730:
            validation_scope.append("Full re-validation due to model age > 2 years")

        overdue_validation = model_age_days > _VALIDATION_FREQUENCY.get(risk_tier, 1095)

        requirements = {
            "model_id": model_id,
            "risk_tier": risk_tier,
            "independent_validation_required": independent_validation_required,
            "validation_scope": validation_scope,
            "validation_frequency_days": _VALIDATION_FREQUENCY.get(risk_tier, 1095),
            "overdue_validation": overdue_validation,
            "overdue_by_days": max(0, model_age_days - _VALIDATION_FREQUENCY.get(risk_tier, 1095)),
            "documentation_requirements": _DOCUMENTATION_REQUIREMENTS.get(
                risk_tier, _DOCUMENTATION_REQUIREMENTS["LOW"]
            ),
            "sr117_sections": [
                "SR 11-7 Section II — Model Risk Management",
                "SR 11-7 Section III — Model Development, Implementation and Use",
            ],
            "occ_guidance": "OCC 2011-12 — Sound Practices for Model Risk Management",
            "mapped_at": datetime.now(timezone.utc).isoformat(),
        }

        if independent_validation_required:
            requirements["validator_independence_requirement"] = (
                "Validator must be independent from model development team. "
                "For CRITICAL/HIGH models, external validation is strongly recommended."
            )

        logger.info(
            "SR 11-7 validation requirements mapped",
            model_id=model_id,
            risk_tier=risk_tier,
            independent_validation_required=independent_validation_required,
            overdue_validation=overdue_validation,
        )

        return requirements

    def monitor_performance(
        self,
        model_id: str,
        model_type: str,
        risk_tier: str,
        performance_observations: dict[str, float],
        baseline_metrics: dict[str, float],
        observation_date: datetime,
    ) -> dict[str, Any]:
        """Monitor model performance against SR 11-7 thresholds.

        Compares current performance observations against baseline metrics
        to detect drift, degradation, and threshold breaches requiring
        management action or model redevelopment.

        Args:
            model_id: Model being monitored.
            model_type: Model type for context-aware threshold selection.
            risk_tier: SR 11-7 risk tier affecting alert sensitivity.
            performance_observations: Current period performance metric values.
            baseline_metrics: Baseline metric values at last validation.
            observation_date: Date of the performance observation.

        Returns:
            Performance monitoring report dict with drift analysis.
        """
        drift_alerts: list[dict[str, Any]] = []
        metric_analyses: list[dict[str, Any]] = []

        # Drift threshold varies by tier — higher tiers trigger earlier
        drift_threshold = {
            "CRITICAL": 0.05,
            "HIGH": 0.10,
            "MEDIUM": 0.15,
            "LOW": 0.20,
        }.get(risk_tier, 0.15)

        for metric_name, observed_value in performance_observations.items():
            baseline_value = baseline_metrics.get(metric_name)
            if baseline_value is None:
                continue

            if baseline_value != 0:
                relative_change = abs(observed_value - baseline_value) / abs(baseline_value)
            else:
                relative_change = abs(observed_value)

            breach = relative_change > drift_threshold

            analysis: dict[str, Any] = {
                "metric": metric_name,
                "baseline_value": baseline_value,
                "observed_value": observed_value,
                "relative_change_pct": round(relative_change * 100, 2),
                "drift_threshold_pct": round(drift_threshold * 100, 2),
                "breach": breach,
            }
            metric_analyses.append(analysis)

            if breach:
                drift_alerts.append({
                    "alert_type": "PERFORMANCE_DRIFT",
                    "metric": metric_name,
                    "severity": "HIGH" if risk_tier in ("CRITICAL", "HIGH") else "MEDIUM",
                    "relative_change_pct": round(relative_change * 100, 2),
                    "action_required": "Investigate root cause and consider model recalibration",
                })

        recommended_metrics = _MONITORING_METRICS.get(model_type, ["Performance drift"])
        missing_recommended = [m for m in recommended_metrics if m not in performance_observations]

        monitoring_report = {
            "model_id": model_id,
            "model_type": model_type,
            "risk_tier": risk_tier,
            "observation_date": observation_date.isoformat(),
            "metrics_monitored": len(metric_analyses),
            "drift_threshold_pct": round(drift_threshold * 100, 2),
            "metric_analyses": metric_analyses,
            "drift_alerts": drift_alerts,
            "alert_count": len(drift_alerts),
            "missing_recommended_metrics": missing_recommended,
            "redevelopment_trigger": len(drift_alerts) >= 3 or any(
                a.get("severity") == "HIGH" and a.get("relative_change_pct", 0) > 25
                for a in drift_alerts
            ),
            "sr117_section": "SR 11-7 Section IV — Ongoing Monitoring",
            "monitored_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "SR 11-7 model performance monitored",
            model_id=model_id,
            metrics_monitored=len(metric_analyses),
            alert_count=len(drift_alerts),
            redevelopment_trigger=monitoring_report["redevelopment_trigger"],
        )

        return monitoring_report

    def compare_challenger(
        self,
        champion_model_id: str,
        challenger_model_id: str,
        champion_metrics: dict[str, float],
        challenger_metrics: dict[str, float],
        business_context: str,
        override_justification: str | None = None,
    ) -> dict[str, Any]:
        """Compare champion model against a challenger model.

        Evaluates whether the challenger model provides sufficient
        performance improvement to justify migration, consistent with
        SR 11-7 model change management requirements.

        Args:
            champion_model_id: Current production model ID.
            challenger_model_id: Challenger model ID under evaluation.
            champion_metrics: Champion model performance metrics.
            challenger_metrics: Challenger model performance metrics.
            business_context: Business reason for the challenger evaluation.
            override_justification: Justification if champion is retained despite worse metrics.

        Returns:
            Challenger comparison report dict with migration recommendation.
        """
        comparison_results: list[dict[str, Any]] = []
        challenger_wins = 0
        champion_wins = 0

        all_metrics = set(champion_metrics) | set(challenger_metrics)

        for metric in all_metrics:
            champion_val = champion_metrics.get(metric)
            challenger_val = challenger_metrics.get(metric)

            if champion_val is None or challenger_val is None:
                continue

            # Higher is generally better for most performance metrics
            improvement = challenger_val - champion_val
            improvement_pct = (improvement / abs(champion_val) * 100) if champion_val != 0 else 0.0

            challenger_better = improvement > 0
            if challenger_better:
                challenger_wins += 1
            else:
                champion_wins += 1

            comparison_results.append({
                "metric": metric,
                "champion_value": champion_val,
                "challenger_value": challenger_val,
                "absolute_improvement": round(improvement, 6),
                "relative_improvement_pct": round(improvement_pct, 2),
                "challenger_better": challenger_better,
            })

        total_compared = challenger_wins + champion_wins
        challenger_win_rate = challenger_wins / total_compared if total_compared > 0 else 0.0

        recommendation = "MIGRATE_TO_CHALLENGER" if challenger_win_rate >= 0.60 else "RETAIN_CHAMPION"
        if override_justification and recommendation == "MIGRATE_TO_CHALLENGER":
            recommendation = "CHAMPION_RETAINED_WITH_JUSTIFICATION"

        comparison_report = {
            "comparison_id": str(uuid.uuid4()),
            "champion_model_id": champion_model_id,
            "challenger_model_id": challenger_model_id,
            "business_context": business_context,
            "metrics_compared": len(comparison_results),
            "challenger_wins": challenger_wins,
            "champion_wins": champion_wins,
            "challenger_win_rate": round(challenger_win_rate, 4),
            "metric_comparisons": comparison_results,
            "recommendation": recommendation,
            "migration_requires_mrc_approval": True,
            "migration_requires_validation": True,
            "override_justification": override_justification,
            "sr117_requirement": "SR 11-7 Section III.B — Validation of Challengers",
            "compared_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "SR 11-7 challenger model comparison complete",
            champion_model_id=champion_model_id,
            challenger_model_id=challenger_model_id,
            recommendation=recommendation,
            challenger_win_rate=round(challenger_win_rate, 4),
        )

        return comparison_report

    def generate_mrm_report(
        self,
        tenant_id: uuid.UUID,
        reporting_period_start: datetime,
        reporting_period_end: datetime,
        model_records: list[dict[str, Any]],
        validation_activities: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Generate a comprehensive SR 11-7 Model Risk Management report.

        Produces an MRM committee report summarizing model inventory,
        validation status, risk tier distribution, and open action items
        for executive and regulatory review.

        Args:
            tenant_id: Tenant UUID for scoping.
            reporting_period_start: Start of the MRM reporting period.
            reporting_period_end: End of the MRM reporting period.
            model_records: List of model inventory records.
            validation_activities: List of validation activity records.

        Returns:
            MRM report dict with inventory summary and risk analytics.
        """
        tier_distribution: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        validation_status_dist: dict[str, int] = {}
        overdue_validations: list[dict[str, Any]] = []

        for model in model_records:
            tier = model.get("risk_tier", "LOW")
            tier_distribution[tier] = tier_distribution.get(tier, 0) + 1

            validation_status = model.get("validation_status", "UNKNOWN")
            validation_status_dist[validation_status] = (
                validation_status_dist.get(validation_status, 0) + 1
            )

            next_validation_str = model.get("next_validation_date")
            if next_validation_str:
                next_validation = datetime.fromisoformat(next_validation_str)
                if next_validation < datetime.now(timezone.utc):
                    overdue_validations.append({
                        "model_id": model.get("model_id"),
                        "model_name": model.get("model_name"),
                        "risk_tier": tier,
                        "overdue_since": next_validation_str,
                    })

        total_models = len(model_records)
        high_risk_count = tier_distribution.get("CRITICAL", 0) + tier_distribution.get("HIGH", 0)

        mrm_report = {
            "report_id": str(uuid.uuid4()),
            "tenant_id": str(tenant_id),
            "reporting_period_start": reporting_period_start.isoformat(),
            "reporting_period_end": reporting_period_end.isoformat(),
            "report_type": "SR 11-7 MRM Quarterly Report",
            "inventory_summary": {
                "total_models": total_models,
                "tier_distribution": tier_distribution,
                "high_risk_count": high_risk_count,
                "high_risk_pct": round((high_risk_count / total_models * 100) if total_models > 0 else 0.0, 2),
            },
            "validation_summary": {
                "validation_activities_period": len(validation_activities),
                "validation_status_distribution": validation_status_dist,
                "overdue_validations": overdue_validations,
                "overdue_count": len(overdue_validations),
            },
            "open_action_items": [
                f"Overdue validation: {m['model_name']} ({m['risk_tier']})"
                for m in overdue_validations
            ],
            "regulatory_references": [
                "Federal Reserve SR 11-7 — Guidance on Model Risk Management",
                "OCC 2011-12 — Sound Practices for Model Risk Management",
            ],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "report_version": "1.0",
        }

        logger.info(
            "SR 11-7 MRM report generated",
            tenant_id=str(tenant_id),
            total_models=total_models,
            overdue_validations=len(overdue_validations),
        )

        return mrm_report


__all__ = ["ModelRiskManager"]
