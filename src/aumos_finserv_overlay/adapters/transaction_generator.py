"""Synthetic financial transaction generator adapter.

Produces statistically realistic CSV transaction datasets with configurable
fraud injection rates, transaction types, amounts, and merchant data.
Uses Faker for realistic synthetic identifiers with all PII masked by default.
"""

import csv
import io
import random
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from aumos_common.observability import get_logger

from aumos_finserv_overlay.api.schemas import SyntheticTransactionRequest, TransactionType

logger = get_logger(__name__)

# MCC (Merchant Category Code) distribution for payment transactions
_MCC_CODES = [
    ("5411", "Grocery Stores"),
    ("5812", "Eating Places and Restaurants"),
    ("5912", "Drug Stores and Pharmacies"),
    ("5311", "Department Stores"),
    ("5734", "Computer and Computer Software Stores"),
    ("4814", "Telecommunication Services"),
    ("5541", "Service Stations"),
    ("7011", "Hotels and Motels"),
    ("4511", "Airlines and Air Carriers"),
    ("5999", "Miscellaneous and Specialty Retail Stores"),
]

# Transaction channel distribution
_CHANNELS = ["online", "in_store", "mobile_app", "atm", "wire", "ach"]


class TransactionGenerator:
    """Generates synthetic financial transaction datasets.

    Produces CSV output suitable for ML model training and fraud detection
    pipeline stress-testing. All PII fields are masked (tokenised) when
    pii_masked=True (the default).
    """

    def __init__(self) -> None:
        """Initialise transaction generator."""
        pass

    def _generate_account_id(self, account_index: int, pii_masked: bool) -> str:
        """Generate a synthetic account identifier.

        Args:
            account_index: Account index for deterministic generation.
            pii_masked: Whether to use opaque tokens.

        Returns:
            Account identifier string.
        """
        if pii_masked:
            return f"ACC-{account_index:08d}"
        # Non-masked: realistic-looking but fake account number
        return f"{random.randint(1000, 9999):04d}{random.randint(100000, 999999):06d}"

    def _generate_merchant_name(self, mcc_code: str, merchant_index: int) -> str:
        """Generate a synthetic merchant name.

        Args:
            mcc_code: Merchant category code.
            merchant_index: Merchant index for uniqueness.

        Returns:
            Synthetic merchant name string.
        """
        prefixes = ["Metro", "City", "Quick", "Prime", "Central", "North", "South", "East", "West"]
        suffixes = {
            "5411": "Grocers", "5812": "Restaurant", "5912": "Pharmacy", "5311": "Department Store",
            "5734": "Electronics", "4814": "Telecom", "5541": "Gas Station", "7011": "Hotel",
            "4511": "Airways", "5999": "Retail",
        }
        suffix = suffixes.get(mcc_code, "Merchant")
        prefix = prefixes[merchant_index % len(prefixes)]
        return f"{prefix} {suffix} #{merchant_index:03d}"

    async def generate(
        self,
        request: SyntheticTransactionRequest,
    ) -> tuple[bytes, int, int]:
        """Generate synthetic transactions as CSV bytes.

        Produces a CSV file with columns: transaction_id, timestamp,
        account_from, account_to, amount, currency, transaction_type,
        channel, merchant_name, merchant_mcc, is_fraud, fraud_reason.

        Args:
            request: Transaction generation parameters.

        Returns:
            Tuple of (CSV bytes, fraud_count, legitimate_count).
        """
        logger.info(
            "Starting synthetic transaction generation",
            num_transactions=request.num_transactions,
            fraud_rate=request.fraud_rate,
        )

        rng = random.Random(request.seed)

        # Pre-generate account pool
        accounts = [
            self._generate_account_id(i, request.pii_masked)
            for i in range(request.num_accounts)
        ]

        # Pre-generate merchant pool
        merchants = [
            (mcc, name, self._generate_merchant_name(mcc, idx))
            for idx, (mcc, name) in enumerate(_MCC_CODES * ((request.num_accounts // len(_MCC_CODES)) + 1))
            if idx < max(50, request.num_accounts // 10)
        ]

        # Date range setup
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=request.date_range_days)

        # Amount distribution
        amount_min = float(request.amount_min)
        amount_max = float(request.amount_max)

        # Build CSV in memory
        output = io.StringIO()
        fieldnames = [
            "transaction_id",
            "timestamp",
            "account_from",
            "account_to",
            "amount",
            "currency",
            "transaction_type",
            "channel",
            "is_fraud",
            "fraud_reason",
        ]
        if request.include_merchant_data:
            fieldnames.extend(["merchant_name", "merchant_mcc"])
        if request.include_device_data:
            fieldnames.extend(["device_id", "ip_address"])

        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        fraud_count = 0
        legitimate_count = 0

        transaction_types = request.transaction_types or [TransactionType.PAYMENT]

        for _ in range(request.num_transactions):
            is_fraud = rng.random() < request.fraud_rate
            if is_fraud:
                fraud_count += 1
            else:
                legitimate_count += 1

            # Timestamp within date range
            offset_seconds = rng.uniform(0, request.date_range_days * 86400)
            timestamp = start_date + timedelta(seconds=offset_seconds)

            # Accounts
            account_from = rng.choice(accounts)
            account_to = rng.choice([a for a in accounts if a != account_from])

            # Amount — fraud transactions biased toward higher amounts
            if is_fraud:
                amount = rng.uniform(amount_max * 0.5, amount_max)
            else:
                # Log-normal distribution for realistic transaction amounts
                import math
                log_min = math.log(max(amount_min, 0.01))
                log_max = math.log(max(amount_max, 1.0))
                amount = math.exp(rng.uniform(log_min, log_max))

            amount = max(amount_min, min(amount, amount_max))

            tx_type = rng.choice(transaction_types).value
            channel = rng.choice(_CHANNELS)

            row: dict[str, str | float] = {
                "transaction_id": str(uuid.uuid4()),
                "timestamp": timestamp.isoformat(),
                "account_from": account_from,
                "account_to": account_to,
                "amount": round(amount, 2),
                "currency": request.currency,
                "transaction_type": tx_type,
                "channel": channel,
                "is_fraud": "1" if is_fraud else "0",
                "fraud_reason": "velocity_anomaly" if is_fraud else "",
            }

            if request.include_merchant_data and merchants:
                mcc, mcc_name, merchant_name = rng.choice(merchants)
                row["merchant_name"] = merchant_name
                row["merchant_mcc"] = mcc

            if request.include_device_data:
                row["device_id"] = f"DEV-{rng.randint(100000, 999999)}"
                row["ip_address"] = (
                    f"{rng.randint(10, 200)}.{rng.randint(0, 255)}"
                    f".{rng.randint(0, 255)}.{rng.randint(1, 254)}"
                )

            writer.writerow(row)

        csv_bytes = output.getvalue().encode("utf-8")

        logger.info(
            "Synthetic transaction generation complete",
            total=request.num_transactions,
            fraud_count=fraud_count,
            legitimate_count=legitimate_count,
            bytes_generated=len(csv_bytes),
        )

        return csv_bytes, fraud_count, legitimate_count
