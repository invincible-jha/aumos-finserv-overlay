"""Multi-currency FX rate simulation using Geometric Brownian Motion.

GAP-301: Multi-Currency Synthetic Transaction Support.
"""
from __future__ import annotations

import math
import random
from decimal import Decimal
from typing import NamedTuple

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# ISO 4217 common currency pairs with approximate base rates (as of 2025)
DEFAULT_FX_BASE_RATES: dict[str, Decimal] = {
    "EUR/USD": Decimal("1.0850"),
    "GBP/USD": Decimal("1.2650"),
    "USD/JPY": Decimal("150.25"),
    "USD/CHF": Decimal("0.9050"),
    "AUD/USD": Decimal("0.6530"),
    "USD/CAD": Decimal("1.3620"),
    "USD/CNY": Decimal("7.2400"),
    "USD/INR": Decimal("83.50"),
    "USD/BRL": Decimal("4.9800"),
    "USD/MXN": Decimal("17.05"),
}

# Annualized volatility estimates per currency pair
DEFAULT_FX_VOLATILITIES: dict[str, float] = {
    "EUR/USD": 0.065,
    "GBP/USD": 0.082,
    "USD/JPY": 0.075,
    "USD/CHF": 0.061,
    "AUD/USD": 0.091,
    "USD/CAD": 0.070,
    "USD/CNY": 0.025,
    "USD/INR": 0.035,
    "USD/BRL": 0.155,
    "USD/MXN": 0.130,
}


class FXRate(NamedTuple):
    """Simulated FX rate for a currency pair."""

    currency_pair: str
    rate: Decimal
    base_currency: str
    quote_currency: str


class FXSimulator:
    """Simulates FX rates using Geometric Brownian Motion (GBM).

    GBM ensures FX rates remain positive and exhibit realistic mean-reversion
    and volatility clustering. Used for multi-currency synthetic transaction
    generation for AML model training.

    Formula: S(t) = S(0) * exp((mu - sigma^2/2) * dt + sigma * W(t))
    where W(t) is a Wiener process increment.
    """

    def __init__(
        self,
        base_rates: dict[str, Decimal] | None = None,
        volatilities: dict[str, float] | None = None,
        seed: int | None = None,
    ) -> None:
        self._base_rates = base_rates or DEFAULT_FX_BASE_RATES
        self._volatilities = volatilities or DEFAULT_FX_VOLATILITIES
        self._rng = random.Random(seed)

    def simulate_rate(
        self,
        currency_pair: str,
        drift_annual: float = 0.0,
        horizon_days: int = 1,
    ) -> FXRate:
        """Simulate an FX rate using GBM over a time horizon.

        Args:
            currency_pair: Pair in format BASE/QUOTE (e.g. EUR/USD).
            drift_annual: Annualized drift (risk-neutral: 0.0).
            horizon_days: Number of days to simulate forward.

        Returns:
            FXRate with simulated rate.

        Raises:
            ValueError: If currency pair is not in the base rates table.
        """
        if currency_pair not in self._base_rates:
            raise ValueError(f"Unknown currency pair: {currency_pair}. "
                             f"Supported: {list(self._base_rates)}")

        s0 = float(self._base_rates[currency_pair])
        sigma = self._volatilities.get(currency_pair, 0.08)
        dt = horizon_days / 252.0  # Trading days

        # GBM: S(T) = S(0) * exp((mu - sigma^2/2)*dt + sigma*sqrt(dt)*Z)
        wiener = self._rng.gauss(0, 1)
        log_return = (drift_annual - 0.5 * sigma ** 2) * dt + sigma * math.sqrt(dt) * wiener
        s_t = s0 * math.exp(log_return)

        parts = currency_pair.split("/")
        base, quote = (parts[0], parts[1]) if len(parts) == 2 else (currency_pair, "USD")

        return FXRate(
            currency_pair=currency_pair,
            rate=Decimal(str(round(s_t, 6))),
            base_currency=base,
            quote_currency=quote,
        )

    def convert_to_usd(self, amount: Decimal, from_currency: str) -> Decimal:
        """Convert an amount to USD using simulated GBM rate.

        Args:
            amount: Amount in source currency.
            from_currency: ISO 4217 source currency code.

        Returns:
            Amount in USD.
        """
        if from_currency == "USD":
            return amount

        # Look for direct pair or inverse
        direct_pair = f"{from_currency}/USD"
        inverse_pair = f"USD/{from_currency}"

        if direct_pair in self._base_rates:
            rate = self.simulate_rate(direct_pair).rate
            return (amount * rate).quantize(Decimal("0.01"))
        elif inverse_pair in self._base_rates:
            rate = self.simulate_rate(inverse_pair).rate
            return (amount / rate).quantize(Decimal("0.01"))
        else:
            logger.warning("fx_rate_not_found", from_currency=from_currency)
            return amount  # Return unchanged — log the miss

    def generate_transaction_fx(
        self,
        amount: Decimal,
        currency: str,
    ) -> dict:
        """Generate FX metadata for a synthetic transaction.

        Args:
            amount: Transaction amount in source currency.
            currency: ISO 4217 source currency code.

        Returns:
            Dict with currency_pair, fx_rate, amount_usd_equivalent.
        """
        if currency == "USD":
            return {
                "currency_pair": "USD/USD",
                "fx_rate": Decimal("1.0"),
                "amount_usd_equivalent": amount,
            }

        amount_usd = self.convert_to_usd(amount, currency)
        # Find which pair was used
        direct_pair = f"{currency}/USD"
        inverse_pair = f"USD/{currency}"
        pair = direct_pair if direct_pair in self._base_rates else inverse_pair

        return {
            "currency_pair": pair,
            "fx_rate": self.simulate_rate(pair).rate if pair in self._base_rates else Decimal("1.0"),
            "amount_usd_equivalent": amount_usd,
        }
