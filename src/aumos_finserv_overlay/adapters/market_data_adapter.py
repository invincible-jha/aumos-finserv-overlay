"""Bloomberg/Reuters market data adapter.

GAP-298: Bloomberg/Reuters Integration.
"""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from typing import Literal

from aumos_common.observability import get_logger

logger = get_logger(__name__)

MarketDataProvider = Literal["bloomberg", "refinitiv", "mock"]

# Risk-free rate benchmark identifiers
BENCHMARK_RATES: dict[str, str] = {
    "SOFR": "SOFRRATE Index",
    "EURIBOR_3M": "EUR003M Index",
    "SONIA": "SONIO/N Index",
    "TONAR": "MUTKCALM Index",
    "LIBOR_USD_3M": "US0003M Index",  # Legacy — transition to SOFR
}


class MarketDataSnapshot:
    """Point-in-time market data snapshot."""

    def __init__(
        self,
        symbol: str,
        value: Decimal,
        currency: str,
        source: str,
        fetched_at: datetime,
    ) -> None:
        self.symbol = symbol
        self.value = value
        self.currency = currency
        self.source = source
        self.fetched_at = fetched_at


class MarketDataAdapter:
    """Fetches risk-free rates, equity volatilities, and credit spreads.

    Feature-flagged: Bloomberg BLPAPI licenses are expensive and not
    universally available. Mock mode returns deterministic values for
    testing and development.

    Production deployment requires:
    - Bloomberg: AUMOS_FINSERV_BLOOMBERG_API_KEY + blpapi Python SDK
    - Refinitiv: AUMOS_FINSERV_REFINITIV_APP_KEY + refinitiv-data SDK
    """

    def __init__(self, provider: MarketDataProvider = "mock") -> None:
        self._provider = provider

    async def get_risk_free_rate(self, benchmark: str) -> MarketDataSnapshot:
        """Fetch the current risk-free rate for a benchmark.

        Args:
            benchmark: Rate benchmark key (SOFR, EURIBOR_3M, SONIA, etc.).

        Returns:
            MarketDataSnapshot with current rate as Decimal.

        Raises:
            ValueError: If benchmark is not supported.
        """
        if benchmark not in BENCHMARK_RATES:
            raise ValueError(f"Unknown benchmark rate: {benchmark}. Supported: {list(BENCHMARK_RATES)}")

        if self._provider == "mock":
            return self._mock_rate(benchmark)

        logger.warning(
            "market_data_provider_not_configured",
            provider=self._provider,
            benchmark=benchmark,
        )
        return self._mock_rate(benchmark)

    async def get_equity_volatility(self, ticker: str, window_days: int = 30) -> MarketDataSnapshot:
        """Fetch realized equity volatility for a ticker.

        Args:
            ticker: Equity ticker symbol (e.g. AAPL US Equity).
            window_days: Historical window for volatility computation (days).

        Returns:
            MarketDataSnapshot with annualized volatility as Decimal.
        """
        if self._provider == "mock":
            return MarketDataSnapshot(
                symbol=ticker,
                value=Decimal("0.2500"),  # 25% annualized vol — typical market
                currency="PCT",
                source="mock",
                fetched_at=datetime.now(timezone.utc),
            )
        logger.warning("market_data_equity_vol_not_configured", ticker=ticker)
        return MarketDataSnapshot(
            symbol=ticker,
            value=Decimal("0.2500"),
            currency="PCT",
            source="mock",
            fetched_at=datetime.now(timezone.utc),
        )

    async def get_credit_spread(self, issuer: str, tenor_years: int = 5) -> MarketDataSnapshot:
        """Fetch credit spread over risk-free rate for an issuer.

        Args:
            issuer: Bond issuer identifier or CDS reference entity.
            tenor_years: Spread tenor in years.

        Returns:
            MarketDataSnapshot with spread in basis points.
        """
        if self._provider == "mock":
            return MarketDataSnapshot(
                symbol=f"{issuer}_{tenor_years}Y",
                value=Decimal("150"),  # 150 bps — investment grade corporate
                currency="BPS",
                source="mock",
                fetched_at=datetime.now(timezone.utc),
            )
        logger.warning("market_data_credit_spread_not_configured", issuer=issuer)
        return MarketDataSnapshot(
            symbol=f"{issuer}_{tenor_years}Y",
            value=Decimal("150"),
            currency="BPS",
            source="mock",
            fetched_at=datetime.now(timezone.utc),
        )

    @staticmethod
    def _mock_rate(benchmark: str) -> MarketDataSnapshot:
        """Return deterministic mock rate for testing."""
        _mock_values: dict[str, Decimal] = {
            "SOFR": Decimal("0.0530"),
            "EURIBOR_3M": Decimal("0.0390"),
            "SONIA": Decimal("0.0520"),
            "TONAR": Decimal("0.0010"),
            "LIBOR_USD_3M": Decimal("0.0535"),
        }
        return MarketDataSnapshot(
            symbol=benchmark,
            value=_mock_values.get(benchmark, Decimal("0.0500")),
            currency="PCT",
            source="mock",
            fetched_at=datetime.now(timezone.utc),
        )
