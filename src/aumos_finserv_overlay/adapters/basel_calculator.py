"""Basel III/IV Risk-Weighted Asset calculator.

GAP-295: Basel III/IV Capital Adequacy Calculations.
"""
from __future__ import annotations

import math
from decimal import Decimal
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field
from scipy.stats import norm


class BaselAssetClass(str, Enum):
    """Basel IV asset class classifications per CRR3 Annex VI."""

    CORPORATE = "corporate"
    RETAIL_MORTGAGE = "retail_mortgage"
    RETAIL_OTHER = "retail_other"
    SOVEREIGN = "sovereign"
    BANK = "bank"
    EQUITY = "equity"
    SME_CORPORATE = "sme_corporate"
    SPECIALISED_LENDING = "specialised_lending"


# Basel IV SA risk weights (CRR3 Annex VI, Table 1)
SA_RISK_WEIGHTS: dict[BaselAssetClass, Decimal] = {
    BaselAssetClass.CORPORATE: Decimal("1.00"),
    BaselAssetClass.RETAIL_MORTGAGE: Decimal("0.35"),
    BaselAssetClass.RETAIL_OTHER: Decimal("0.75"),
    BaselAssetClass.SOVEREIGN: Decimal("0.00"),
    BaselAssetClass.BANK: Decimal("0.50"),
    BaselAssetClass.EQUITY: Decimal("1.00"),
    BaselAssetClass.SME_CORPORATE: Decimal("0.85"),
    BaselAssetClass.SPECIALISED_LENDING: Decimal("1.00"),
}

# Output floor: 72.5% of SA RWA (Basel IV Article 92a)
OUTPUT_FLOOR_FACTOR: Decimal = Decimal("0.725")


class CreditExposure(BaseModel):
    """Single credit exposure for RWA computation."""

    asset_class: BaselAssetClass
    exposure_at_default_usd: Decimal
    probability_of_default: Decimal = Field(ge=0, le=1)
    loss_given_default: Decimal = Field(ge=0, le=1)
    maturity_years: Decimal = Field(default=Decimal("2.5"), ge=Decimal("0.25"), le=Decimal("5.0"))
    approach: Literal["SA", "F-IRB", "A-IRB"] = "SA"


class RWAResult(BaseModel):
    """RWA computation result per Basel III/IV."""

    exposure_at_default_usd: Decimal
    risk_weight: Decimal
    risk_weighted_asset_usd: Decimal
    approach_used: str
    output_floor_applies: bool
    capital_requirement_usd: Decimal
    regulatory_capital_ratio: Decimal


class BaselCapitalCalculator:
    """Computes Basel III/IV RWA under SA, F-IRB, and A-IRB approaches.

    Implements CRR3 (EU) and aligns with US Basel endgame NPR (December 2023).
    IRB formula uses ASRF model per Basel III paragraph 272.
    scipy.stats.norm used for the Normal CDF — Taylor series approximation
    introduces errors exceeding Basel's required precision at extreme PD values.
    """

    def compute_rwa(self, exposure: CreditExposure) -> RWAResult:
        """Compute RWA for a single credit exposure.

        Args:
            exposure: CreditExposure with asset class, EAD, PD, LGD, maturity.

        Returns:
            RWAResult with risk weight, RWA, and capital requirement.
        """
        if exposure.approach == "SA":
            risk_weight = SA_RISK_WEIGHTS.get(exposure.asset_class, Decimal("1.00"))
            rwa = exposure.exposure_at_default_usd * risk_weight
            output_floor_applies = False
        else:
            risk_weight = self._irb_risk_weight(exposure)
            rwa_irb = exposure.exposure_at_default_usd * risk_weight
            rwa_sa = exposure.exposure_at_default_usd * SA_RISK_WEIGHTS.get(
                exposure.asset_class, Decimal("1.00")
            )
            output_floor_rwa = rwa_sa * OUTPUT_FLOOR_FACTOR
            output_floor_applies = rwa_irb < output_floor_rwa
            rwa = max(rwa_irb, output_floor_rwa)
            risk_weight = rwa / exposure.exposure_at_default_usd

        # Pillar 1 minimum capital requirement (8%)
        capital_requirement = rwa * Decimal("0.08")

        return RWAResult(
            exposure_at_default_usd=exposure.exposure_at_default_usd,
            risk_weight=risk_weight,
            risk_weighted_asset_usd=rwa,
            approach_used=exposure.approach,
            output_floor_applies=output_floor_applies,
            capital_requirement_usd=capital_requirement,
            regulatory_capital_ratio=Decimal("0.08"),
        )

    def _irb_risk_weight(self, exposure: CreditExposure) -> Decimal:
        """Compute IRB risk weight using the Basel ASRF supervisory formula.

        Per Basel III paragraph 272 (ASRF model).
        """
        pd = float(exposure.probability_of_default)
        lgd = float(exposure.loss_given_default)
        m = float(exposure.maturity_years)

        # Correlation (rho) — Basel III para 272
        rho = 0.12 * (1 - math.exp(-50 * pd)) / (1 - math.exp(-50)) + 0.24 * (
            1 - (1 - math.exp(-50 * pd)) / (1 - math.exp(-50))
        )

        # Maturity adjustment
        b = (0.11852 - 0.05478 * math.log(max(pd, 1e-10))) ** 2

        # Conditional PD at 99.9% confidence (ASRF model)
        g_pd = norm.ppf(max(pd, 1e-10))
        g_confidence = norm.ppf(0.999)
        pd_conditional = norm.cdf(
            (g_pd + math.sqrt(rho) * g_confidence) / math.sqrt(1 - rho)
        )

        # Capital requirement K
        k = (lgd * pd_conditional - pd * lgd) * (
            (1 + (m - 2.5) * b) / (1 - 1.5 * b)
        )
        risk_weight = max(k * 12.5, 0.0)
        return Decimal(str(round(risk_weight, 6)))

    def assess_portfolio(self, exposures: list[CreditExposure]) -> dict:
        """Compute aggregate RWA for a portfolio of exposures.

        Args:
            exposures: List of CreditExposure records.

        Returns:
            Dict with total_rwa_usd, total_capital_requirement_usd,
            exposure_count, and per-exposure results.
        """
        results = [self.compute_rwa(exp) for exp in exposures]
        total_rwa = sum(r.risk_weighted_asset_usd for r in results)
        total_capital = sum(r.capital_requirement_usd for r in results)
        return {
            "total_rwa_usd": total_rwa,
            "total_capital_requirement_usd": total_capital,
            "exposure_count": len(results),
            "results": [r.model_dump() for r in results],
        }
