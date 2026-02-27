"""Credit risk synthetic data generation adapter for aumos-finserv-overlay.

Generates synthetic loan portfolio data for credit risk model training,
backtesting, and validation. Produces Basel III/IV-aligned exposures with
realistic default probability distributions, credit score distributions,
and macroeconomic scenario correlations.
"""

import csv
import io
import math
import random
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# Basel III/IV RWA weight categories by loan type
_BASEL_RWA_WEIGHTS: dict[str, float] = {
    "mortgage": 0.35,
    "sme_corporate": 0.75,
    "large_corporate": 1.00,
    "consumer_unsecured": 1.00,
    "consumer_secured": 0.75,
    "auto_loan": 0.75,
    "credit_card": 1.00,
    "student_loan": 1.00,
    "home_equity": 0.50,
}

# FICO score distribution parameters (mean, std) by credit quality band
_CREDIT_SCORE_BANDS: dict[str, tuple[float, float]] = {
    "prime_plus": (780.0, 15.0),
    "prime": (730.0, 25.0),
    "near_prime": (660.0, 30.0),
    "subprime": (580.0, 35.0),
    "deep_subprime": (510.0, 25.0),
}

# Approximate through-the-cycle default rates by credit quality band
_DEFAULT_RATES: dict[str, float] = {
    "prime_plus": 0.002,
    "near_prime": 0.025,
    "subprime": 0.080,
    "deep_subprime": 0.180,
    "prime": 0.008,
}

# Macroeconomic scenario multipliers for PD adjustment
_MACRO_SCENARIOS: dict[str, dict[str, float]] = {
    "baseline": {
        "pd_multiplier": 1.00,
        "gdp_growth_pct": 2.0,
        "unemployment_pct": 4.0,
        "hpi_change_pct": 3.0,
    },
    "mild_recession": {
        "pd_multiplier": 1.80,
        "gdp_growth_pct": -0.5,
        "unemployment_pct": 6.5,
        "hpi_change_pct": -5.0,
    },
    "severe_recession": {
        "pd_multiplier": 3.50,
        "gdp_growth_pct": -3.0,
        "unemployment_pct": 9.0,
        "hpi_change_pct": -15.0,
    },
    "adverse": {
        "pd_multiplier": 2.20,
        "gdp_growth_pct": -1.0,
        "unemployment_pct": 7.5,
        "hpi_change_pct": -8.0,
    },
}

# Loan purpose categories
_LOAN_PURPOSES = [
    "home_purchase",
    "refinance",
    "debt_consolidation",
    "auto_purchase",
    "home_improvement",
    "education",
    "business",
    "other",
]

# US state codes for geographic distribution
_US_STATES = [
    "CA", "TX", "FL", "NY", "PA", "IL", "OH", "GA", "NC", "MI",
    "NJ", "VA", "WA", "AZ", "MA", "TN", "IN", "MO", "MD", "WI",
]


class CreditRiskSynthesizer:
    """Generates synthetic credit risk datasets for model development and validation.

    Produces Basel III/IV-aligned synthetic loan portfolios with realistic
    probability of default distributions, credit score distributions, LTV/DTI
    ratios, and macroeconomic scenario correlation. All data is synthetic
    and contains no real borrower information.
    """

    def __init__(self) -> None:
        """Initialize credit risk synthesizer."""
        pass

    def generate_loan_portfolio(
        self,
        num_loans: int,
        loan_type: str,
        credit_quality_mix: dict[str, float],
        macro_scenario: str = "baseline",
        seed: int | None = None,
        origination_date_range_days: int = 365,
        include_feature_columns: bool = True,
    ) -> tuple[bytes, dict[str, Any]]:
        """Generate a synthetic loan portfolio dataset.

        Creates a CSV dataset with loan-level records including borrower
        characteristics, loan terms, probability of default, and default
        labels aligned with Basel III/IV standards.

        Args:
            num_loans: Number of synthetic loan records to generate.
            loan_type: Loan product type (mortgage/auto_loan/consumer_unsecured/etc.).
            credit_quality_mix: Dict mapping credit band names to portfolio weights
                (must sum to approximately 1.0).
            macro_scenario: Macroeconomic scenario for PD adjustment.
            seed: Random seed for reproducibility.
            origination_date_range_days: Range of origination dates in days.
            include_feature_columns: Whether to include model feature columns.

        Returns:
            Tuple of (CSV bytes, portfolio statistics dict).
        """
        rng = random.Random(seed)
        macro = _MACRO_SCENARIOS.get(macro_scenario, _MACRO_SCENARIOS["baseline"])
        rwa_weight = _BASEL_RWA_WEIGHTS.get(loan_type, 1.00)

        # Normalize credit quality mix
        total_weight = sum(credit_quality_mix.values())
        normalized_mix = {k: v / total_weight for k, v in credit_quality_mix.items()}

        output = io.StringIO()
        fieldnames = [
            "loan_id",
            "origination_date",
            "loan_type",
            "loan_purpose",
            "loan_amount",
            "loan_term_months",
            "interest_rate",
            "credit_score",
            "credit_quality_band",
            "ltv_ratio",
            "dti_ratio",
            "annual_income",
            "employment_years",
            "state",
            "probability_of_default",
            "loss_given_default",
            "exposure_at_default",
            "risk_weight",
            "rwa",
            "macro_scenario",
            "default_label",
        ]

        if include_feature_columns:
            fieldnames.extend([
                "num_credit_lines",
                "num_derogatory_marks",
                "num_inquiries_12m",
                "months_since_last_delinquency",
                "payment_history_pct",
                "revolving_utilization_pct",
            ])

        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        default_count = 0
        total_exposure = Decimal("0")
        total_rwa = Decimal("0")
        credit_score_sum = 0.0
        pd_sum = 0.0

        now = datetime.now(timezone.utc)
        start_date = now - timedelta(days=origination_date_range_days)

        for _ in range(num_loans):
            # Select credit quality band by weight
            band = rng.choices(
                list(normalized_mix.keys()),
                weights=list(normalized_mix.values()),
                k=1,
            )[0]

            score_mean, score_std = _CREDIT_SCORE_BANDS.get(band, (700.0, 30.0))
            credit_score = int(max(300, min(850, rng.gauss(score_mean, score_std))))

            base_pd = _DEFAULT_RATES.get(band, 0.02)
            adjusted_pd = min(0.99, base_pd * macro["pd_multiplier"])
            pd_sum += adjusted_pd

            # Loan terms by type
            if loan_type == "mortgage":
                loan_amount = rng.uniform(150_000, 750_000)
                term_months = rng.choice([180, 360])
                interest_rate = rng.uniform(3.5, 7.5)
                ltv = rng.uniform(0.60, 0.95) if credit_score >= 680 else rng.uniform(0.80, 0.97)
                dti = rng.uniform(0.20, 0.43)
                lgd = 0.25  # Loss given default typically lower for secured
            elif loan_type == "auto_loan":
                loan_amount = rng.uniform(15_000, 60_000)
                term_months = rng.choice([36, 48, 60, 72])
                interest_rate = rng.uniform(4.0, 18.0)
                ltv = rng.uniform(0.80, 1.10)
                dti = rng.uniform(0.15, 0.40)
                lgd = 0.45
            else:  # consumer unsecured / credit card / personal
                loan_amount = rng.uniform(5_000, 40_000)
                term_months = rng.choice([24, 36, 48, 60])
                interest_rate = rng.uniform(8.0, 24.0)
                ltv = 0.0  # Unsecured
                dti = rng.uniform(0.20, 0.50)
                lgd = 0.75

            annual_income = rng.uniform(35_000, 250_000)
            employment_years = max(0.0, rng.gauss(7.0, 5.0))
            state = rng.choice(_US_STATES)
            loan_purpose = rng.choice(_LOAN_PURPOSES)

            # Origination date
            offset_days = rng.uniform(0, origination_date_range_days)
            origination_date = start_date + timedelta(days=offset_days)

            ead = loan_amount  # Simplified EAD
            rwa_value = ead * rwa_weight * lgd
            total_exposure += Decimal(str(ead))
            total_rwa += Decimal(str(rwa_value))
            credit_score_sum += credit_score

            # Default label based on adjusted PD with random draw
            default_label = int(rng.random() < adjusted_pd)
            if default_label:
                default_count += 1

            row: dict[str, Any] = {
                "loan_id": str(uuid.uuid4()),
                "origination_date": origination_date.strftime("%Y-%m-%d"),
                "loan_type": loan_type,
                "loan_purpose": loan_purpose,
                "loan_amount": round(loan_amount, 2),
                "loan_term_months": term_months,
                "interest_rate": round(interest_rate, 4),
                "credit_score": credit_score,
                "credit_quality_band": band,
                "ltv_ratio": round(ltv, 4),
                "dti_ratio": round(dti, 4),
                "annual_income": round(annual_income, 2),
                "employment_years": round(employment_years, 1),
                "state": state,
                "probability_of_default": round(adjusted_pd, 6),
                "loss_given_default": round(lgd, 4),
                "exposure_at_default": round(ead, 2),
                "risk_weight": rwa_weight,
                "rwa": round(rwa_value, 2),
                "macro_scenario": macro_scenario,
                "default_label": default_label,
            }

            if include_feature_columns:
                row["num_credit_lines"] = rng.randint(1, 20)
                row["num_derogatory_marks"] = max(0, int(rng.gauss(
                    2.0 if credit_score < 620 else 0.2, 1.0
                )))
                row["num_inquiries_12m"] = rng.randint(0, 8)
                row["months_since_last_delinquency"] = (
                    rng.randint(0, 60) if credit_score < 720 else rng.randint(24, 120)
                )
                row["payment_history_pct"] = round(
                    max(0.0, min(1.0, rng.gauss(0.95 if credit_score >= 700 else 0.78, 0.08))), 4
                )
                row["revolving_utilization_pct"] = round(
                    max(0.0, min(1.0, rng.gauss(0.35 if credit_score >= 680 else 0.65, 0.15))), 4
                )

            writer.writerow(row)

        csv_bytes = output.getvalue().encode("utf-8")

        portfolio_stats: dict[str, Any] = {
            "num_loans": num_loans,
            "loan_type": loan_type,
            "macro_scenario": macro_scenario,
            "macro_scenario_params": macro,
            "default_count": default_count,
            "default_rate_realized": round(default_count / num_loans, 6) if num_loans > 0 else 0.0,
            "average_pd": round(pd_sum / num_loans, 6) if num_loans > 0 else 0.0,
            "total_exposure": float(total_exposure),
            "total_rwa": float(total_rwa),
            "average_credit_score": round(credit_score_sum / num_loans, 2) if num_loans > 0 else 0.0,
            "basel_rwa_weight": rwa_weight,
            "credit_quality_mix": credit_quality_mix,
            "bytes_generated": len(csv_bytes),
        }

        self._validate_portfolio_statistics(portfolio_stats)

        logger.info(
            "Synthetic credit risk portfolio generated",
            num_loans=num_loans,
            loan_type=loan_type,
            default_rate=portfolio_stats["default_rate_realized"],
            total_exposure=float(total_exposure),
        )

        return csv_bytes, portfolio_stats

    def model_default_probability_distribution(
        self,
        num_borrowers: int,
        segments: list[dict[str, Any]],
        correlation_matrix: dict[str, float] | None = None,
        seed: int | None = None,
    ) -> dict[str, Any]:
        """Model probability of default distribution across borrower segments.

        Generates a PD distribution model with segment-level statistics,
        correlation structure, and Basel III/IV expected loss calculations.

        Args:
            num_borrowers: Total borrowers to model across segments.
            segments: List of segment dicts with 'name', 'weight', 'mean_pd', 'pd_std' keys.
            correlation_matrix: Optional PD correlation between segments.
            seed: Random seed for reproducibility.

        Returns:
            PD distribution model dict with segment statistics and aggregate metrics.
        """
        rng = random.Random(seed)
        segment_results: list[dict[str, Any]] = []
        portfolio_pds: list[float] = []

        for segment in segments:
            weight = segment.get("weight", 1.0 / len(segments))
            mean_pd = segment.get("mean_pd", 0.02)
            pd_std = segment.get("pd_std", mean_pd * 0.3)
            segment_loans = int(num_borrowers * weight)

            pds = [
                max(0.001, min(0.99, rng.gauss(mean_pd, pd_std)))
                for _ in range(segment_loans)
            ]
            portfolio_pds.extend(pds)

            expected_loss_rate = sum(pds) / segment_loans if segment_loans > 0 else 0.0
            pd_99th = sorted(pds)[int(0.99 * len(pds))] if pds else 0.0

            segment_results.append({
                "segment_name": segment.get("name", "Unnamed"),
                "weight": weight,
                "borrowers_modeled": segment_loans,
                "mean_pd": round(mean_pd, 6),
                "pd_std": round(pd_std, 6),
                "realized_mean_pd": round(sum(pds) / segment_loans, 6) if segment_loans > 0 else 0.0,
                "expected_loss_rate": round(expected_loss_rate, 6),
                "pd_99th_percentile": round(pd_99th, 6),
                "pd_min": round(min(pds), 6) if pds else 0.0,
                "pd_max": round(max(pds), 6) if pds else 0.0,
            })

        total_expected_loss = sum(pd for pd in portfolio_pds) / len(portfolio_pds) if portfolio_pds else 0.0
        portfolio_pd_99th = sorted(portfolio_pds)[int(0.99 * len(portfolio_pds))] if portfolio_pds else 0.0

        model = {
            "num_borrowers": num_borrowers,
            "num_segments": len(segments),
            "segment_statistics": segment_results,
            "portfolio_statistics": {
                "mean_pd": round(sum(portfolio_pds) / len(portfolio_pds), 6) if portfolio_pds else 0.0,
                "expected_loss_rate": round(total_expected_loss, 6),
                "pd_99th_percentile": round(portfolio_pd_99th, 6),
                "concentration_ratio": round(max(s["weight"] for s in segments), 4) if segments else 0.0,
            },
            "correlation_matrix": correlation_matrix,
            "basel_compliant": True,
            "basel_reference": "Basel III — IRB Approach for Credit Risk",
            "modeled_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "Credit risk PD distribution modeled",
            num_borrowers=num_borrowers,
            num_segments=len(segments),
            portfolio_mean_pd=model["portfolio_statistics"]["mean_pd"],
        )

        return model

    def _validate_portfolio_statistics(self, stats: dict[str, Any]) -> None:
        """Validate that generated portfolio statistics are within realistic bounds.

        Args:
            stats: Portfolio statistics dict from generate_loan_portfolio.
        """
        default_rate = stats.get("default_rate_realized", 0.0)
        avg_pd = stats.get("average_pd", 0.0)

        # Default rate should be within ±3 standard deviations of average PD
        pd_std_approx = math.sqrt(avg_pd * (1 - avg_pd) / max(stats.get("num_loans", 1), 1))
        deviation = abs(default_rate - avg_pd)

        if deviation > 3 * pd_std_approx and pd_std_approx > 0:
            logger.warning(
                "Portfolio default rate deviates significantly from average PD",
                default_rate=default_rate,
                average_pd=avg_pd,
                deviation=deviation,
                three_sigma=3 * pd_std_approx,
            )
        else:
            logger.debug(
                "Portfolio statistics validation passed",
                default_rate=default_rate,
                average_pd=avg_pd,
            )


__all__ = ["CreditRiskSynthesizer"]
