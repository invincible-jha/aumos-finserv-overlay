"""Synthetic fraud pattern generation adapter for aumos-finserv-overlay.

Generates realistic synthetic financial fraud datasets for fraud detection
model training, validation, and stress testing. Produces labeled fraud
patterns including card-not-present, account takeover, fraud rings,
temporal patterns, and geographic patterns.
"""

import csv
import io
import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# Fraud typology definitions with characteristics
_FRAUD_TYPOLOGIES: dict[str, dict[str, Any]] = {
    "card_not_present": {
        "description": "CNP fraud — card credentials used in online transactions",
        "typical_amount_range": (50.0, 2000.0),
        "velocity_indicators": True,
        "typical_channels": ["online", "mobile_app", "phone"],
        "time_of_day_bias": "evening",
        "geographic_pattern": "distant_from_home",
        "mcc_bias": ["5968", "5999", "5734", "4816"],  # Online merchants
    },
    "account_takeover": {
        "description": "ATO — unauthorized access to legitimate account",
        "typical_amount_range": (200.0, 5000.0),
        "velocity_indicators": True,
        "typical_channels": ["online", "mobile_app", "atm"],
        "time_of_day_bias": "night",
        "geographic_pattern": "new_device_new_location",
        "mcc_bias": ["6011", "7012", "5999"],  # Cash, wire, online
    },
    "structuring": {
        "description": "Transaction structuring below CTR threshold",
        "typical_amount_range": (8500.0, 9999.0),
        "velocity_indicators": True,
        "typical_channels": ["atm", "branch", "wire"],
        "time_of_day_bias": "business_hours",
        "geographic_pattern": "multiple_branches",
        "mcc_bias": ["6011", "6012"],  # Banking
    },
    "bust_out": {
        "description": "Credit bust-out — max credit then default",
        "typical_amount_range": (500.0, 10000.0),
        "velocity_indicators": True,
        "typical_channels": ["online", "in_store"],
        "time_of_day_bias": "any",
        "geographic_pattern": "home_location",
        "mcc_bias": ["5311", "5411", "5734", "5912"],  # Retail
    },
    "synthetic_identity": {
        "description": "Fabricated identity combining real and fake information",
        "typical_amount_range": (100.0, 8000.0),
        "velocity_indicators": False,
        "typical_channels": ["online", "in_store"],
        "time_of_day_bias": "any",
        "geographic_pattern": "home_location",
        "mcc_bias": ["6022", "5311"],
    },
    "friendly_fraud": {
        "description": "Legitimate cardholder disputes valid transaction",
        "typical_amount_range": (50.0, 800.0),
        "velocity_indicators": False,
        "typical_channels": ["online"],
        "time_of_day_bias": "any",
        "geographic_pattern": "home_location",
        "mcc_bias": ["5999", "5734", "5968"],
    },
    "first_party_fraud": {
        "description": "Borrower intentionally defaults with no intention to repay",
        "typical_amount_range": (1000.0, 50000.0),
        "velocity_indicators": False,
        "typical_channels": ["branch", "online"],
        "time_of_day_bias": "business_hours",
        "geographic_pattern": "home_location",
        "mcc_bias": ["6159"],
    },
}

# Fraud ring configuration — shared account pools simulate organized crime
_RING_SIZES = [3, 5, 8, 12, 20]

# Geographic regions for pattern generation
_REGIONS: dict[str, list[str]] = {
    "northeast_us": ["New York, NY", "Boston, MA", "Philadelphia, PA", "Newark, NJ"],
    "southeast_us": ["Miami, FL", "Atlanta, GA", "Charlotte, NC", "Tampa, FL"],
    "west_coast": ["Los Angeles, CA", "San Francisco, CA", "Seattle, WA", "Portland, OR"],
    "midwest": ["Chicago, IL", "Detroit, MI", "Columbus, OH", "Minneapolis, MN"],
    "international": ["London, GB", "Toronto, CA", "Mexico City, MX", "Lagos, NG"],
}

# Merchant category codes for labeling
_MERCHANT_NAMES: dict[str, str] = {
    "5968": "Online Subscription Service",
    "5999": "Online Retailer",
    "5734": "Computer Store",
    "4816": "Digital Media Provider",
    "6011": "ATM Cash Withdrawal",
    "6012": "Financial Institution",
    "7012": "Accommodation Service",
    "5311": "Department Store",
    "5411": "Grocery Store",
    "5912": "Pharmacy",
    "6022": "State Member Bank",
    "6159": "Federal Sponsored Loan",
    "5541": "Gas Station",
    "4814": "Telecom Service",
}


class FraudPatternGenerator:
    """Generates synthetic financial fraud pattern datasets.

    Produces labeled fraud and legitimate transaction datasets with configurable
    fraud typologies, ring structures, temporal patterns, amount distributions,
    and geographic diversity. Suitable for supervised fraud model training,
    anomaly detection, and rule engine validation.
    """

    def __init__(self) -> None:
        """Initialize fraud pattern generator."""
        pass

    def generate_fraud_dataset(
        self,
        num_total_transactions: int,
        fraud_rate: float,
        typology_mix: dict[str, float] | None = None,
        include_rings: bool = True,
        ring_count: int = 3,
        seed: int | None = None,
        date_range_days: int = 90,
    ) -> tuple[bytes, dict[str, Any]]:
        """Generate a labeled synthetic fraud transaction dataset.

        Produces a CSV dataset with transaction records spanning multiple
        fraud typologies, optional fraud ring structures, and realistic
        temporal, amount, and geographic distributions.

        Args:
            num_total_transactions: Total transaction records to generate.
            fraud_rate: Proportion of transactions to label as fraud (0.0–1.0).
            typology_mix: Dict mapping typology names to relative weights.
                If None, defaults to balanced distribution.
            include_rings: Whether to generate fraud ring transaction clusters.
            ring_count: Number of fraud rings to generate.
            seed: Random seed for reproducibility.
            date_range_days: Date range to distribute transactions over.

        Returns:
            Tuple of (CSV bytes, fraud statistics dict).
        """
        rng = random.Random(seed)

        if typology_mix is None:
            available = list(_FRAUD_TYPOLOGIES.keys())
            typology_mix = {t: 1.0 / len(available) for t in available}

        # Normalize typology weights
        total_weight = sum(typology_mix.values())
        normalized_typology = {k: v / total_weight for k, v in typology_mix.items()}

        num_fraud = int(num_total_transactions * fraud_rate)
        num_legitimate = num_total_transactions - num_fraud

        # Build fraud ring account pools
        ring_accounts: list[list[str]] = []
        if include_rings and ring_count > 0:
            ring_accounts = self._generate_rings(ring_count, rng)

        now = datetime.now(timezone.utc)
        start_date = now - timedelta(days=date_range_days)

        output = io.StringIO()
        fieldnames = [
            "transaction_id",
            "timestamp",
            "account_id",
            "counterparty_account_id",
            "amount",
            "currency",
            "channel",
            "merchant_mcc",
            "merchant_name",
            "location",
            "device_id",
            "ip_address",
            "fraud_label",
            "fraud_typology",
            "fraud_ring_id",
            "velocity_flag",
            "amount_flag",
            "geo_flag",
        ]

        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        typology_counts: dict[str, int] = {k: 0 for k in normalized_typology}
        legitimate_count = 0
        fraud_count = 0

        # Generate fraud transactions
        for i in range(num_fraud):
            typology_name = rng.choices(
                list(normalized_typology.keys()),
                weights=list(normalized_typology.values()),
                k=1,
            )[0]
            typology = _FRAUD_TYPOLOGIES[typology_name]
            typology_counts[typology_name] += 1

            # Determine if this fraud belongs to a ring
            ring_id: str | None = None
            account_id: str
            if ring_accounts and rng.random() < 0.30:
                ring_index = rng.randint(0, len(ring_accounts) - 1)
                account_id = rng.choice(ring_accounts[ring_index])
                ring_id = f"RING-{ring_index:04d}"
            else:
                account_id = f"ACC-{rng.randint(100000, 999999):06d}"

            row = self._generate_fraud_transaction(
                transaction_index=i,
                typology_name=typology_name,
                typology=typology,
                account_id=account_id,
                ring_id=ring_id,
                start_date=start_date,
                date_range_days=date_range_days,
                rng=rng,
            )
            writer.writerow(row)
            fraud_count += 1

        # Generate legitimate transactions
        for j in range(num_legitimate):
            row = self._generate_legitimate_transaction(
                transaction_index=j,
                start_date=start_date,
                date_range_days=date_range_days,
                rng=rng,
            )
            writer.writerow(row)
            legitimate_count += 1

        csv_bytes = output.getvalue().encode("utf-8")

        stats: dict[str, Any] = {
            "total_transactions": num_total_transactions,
            "fraud_count": fraud_count,
            "legitimate_count": legitimate_count,
            "fraud_rate_realized": round(fraud_count / num_total_transactions, 6) if num_total_transactions > 0 else 0.0,
            "typology_distribution": typology_counts,
            "ring_count": ring_count if include_rings else 0,
            "ring_accounts_generated": sum(len(r) for r in ring_accounts),
            "date_range_days": date_range_days,
            "bytes_generated": len(csv_bytes),
        }

        logger.info(
            "Synthetic fraud dataset generated",
            total_transactions=num_total_transactions,
            fraud_count=fraud_count,
            legitimate_count=legitimate_count,
            typologies=list(typology_counts.keys()),
        )

        return csv_bytes, stats

    def _generate_rings(
        self,
        ring_count: int,
        rng: random.Random,
    ) -> list[list[str]]:
        """Generate fraud ring account pools.

        Args:
            ring_count: Number of fraud rings to generate.
            rng: Seeded random number generator.

        Returns:
            List of account ID lists, one per ring.
        """
        rings: list[list[str]] = []
        for ring_index in range(ring_count):
            size = rng.choice(_RING_SIZES)
            ring = [f"RING-{ring_index:04d}-ACC-{member:04d}" for member in range(size)]
            rings.append(ring)
        return rings

    def _generate_fraud_transaction(
        self,
        transaction_index: int,
        typology_name: str,
        typology: dict[str, Any],
        account_id: str,
        ring_id: str | None,
        start_date: datetime,
        date_range_days: int,
        rng: random.Random,
    ) -> dict[str, Any]:
        """Generate a single synthetic fraud transaction.

        Args:
            transaction_index: Sequential index for uniqueness.
            typology_name: Fraud typology identifier.
            typology: Typology configuration dict.
            account_id: Account identifier (possibly ring-shared).
            ring_id: Optional ring identifier.
            start_date: Earliest possible transaction timestamp.
            date_range_days: Date range in days.
            rng: Seeded random generator.

        Returns:
            Transaction row dict.
        """
        amount_min, amount_max = typology["typical_amount_range"]
        amount = round(rng.uniform(amount_min, amount_max), 2)

        offset_seconds = rng.uniform(0, date_range_days * 86400)
        timestamp = start_date + timedelta(seconds=offset_seconds)

        # Apply time-of-day bias
        time_bias = typology.get("time_of_day_bias", "any")
        if time_bias == "evening":
            timestamp = timestamp.replace(hour=rng.randint(18, 23))
        elif time_bias == "night":
            timestamp = timestamp.replace(hour=rng.randint(0, 5))
        elif time_bias == "business_hours":
            timestamp = timestamp.replace(hour=rng.randint(9, 17))

        channel = rng.choice(typology.get("typical_channels", ["online"]))
        mcc_options = typology.get("mcc_bias", ["5999"])
        mcc = rng.choice(mcc_options)
        merchant_name = _MERCHANT_NAMES.get(mcc, "Online Merchant")

        geo_pattern = typology.get("geographic_pattern", "home_location")
        if geo_pattern in ("distant_from_home", "new_device_new_location"):
            all_locations = [loc for locs in _REGIONS.values() for loc in locs]
            location = rng.choice(all_locations)
            geo_flag = True
        else:
            location = rng.choice(_REGIONS.get("northeast_us", ["New York, NY"]))
            geo_flag = False

        velocity_flag = typology.get("velocity_indicators", False) and rng.random() < 0.6
        amount_flag = amount > 5000.0

        return {
            "transaction_id": str(uuid.uuid4()),
            "timestamp": timestamp.isoformat(),
            "account_id": account_id,
            "counterparty_account_id": f"MERCHANT-{rng.randint(10000, 99999):05d}",
            "amount": amount,
            "currency": "USD",
            "channel": channel,
            "merchant_mcc": mcc,
            "merchant_name": merchant_name,
            "location": location,
            "device_id": f"DEV-{rng.randint(100000, 999999):06d}",
            "ip_address": (
                f"{rng.randint(1, 254)}.{rng.randint(0, 255)}"
                f".{rng.randint(0, 255)}.{rng.randint(1, 254)}"
            ),
            "fraud_label": 1,
            "fraud_typology": typology_name,
            "fraud_ring_id": ring_id or "",
            "velocity_flag": int(velocity_flag),
            "amount_flag": int(amount_flag),
            "geo_flag": int(geo_flag),
        }

    def _generate_legitimate_transaction(
        self,
        transaction_index: int,
        start_date: datetime,
        date_range_days: int,
        rng: random.Random,
    ) -> dict[str, Any]:
        """Generate a single synthetic legitimate transaction.

        Args:
            transaction_index: Sequential index.
            start_date: Earliest possible timestamp.
            date_range_days: Date range in days.
            rng: Seeded random generator.

        Returns:
            Transaction row dict.
        """
        import math
        amount_log = rng.gauss(4.5, 1.2)  # Log-normal amounts centered ~$90
        amount = round(max(1.0, math.exp(amount_log)), 2)

        offset_seconds = rng.uniform(0, date_range_days * 86400)
        timestamp = start_date + timedelta(seconds=offset_seconds)

        channels = ["online", "in_store", "mobile_app", "atm"]
        channel = rng.choices(channels, weights=[0.35, 0.40, 0.15, 0.10], k=1)[0]

        mccs = list(_MERCHANT_NAMES.keys())
        mcc = rng.choice(mccs)

        home_region = rng.choice(list(_REGIONS.keys())[:4])
        location = rng.choice(_REGIONS[home_region])

        return {
            "transaction_id": str(uuid.uuid4()),
            "timestamp": timestamp.isoformat(),
            "account_id": f"ACC-{transaction_index % 50000:06d}",
            "counterparty_account_id": f"MERCHANT-{rng.randint(10000, 99999):05d}",
            "amount": amount,
            "currency": "USD",
            "channel": channel,
            "merchant_mcc": mcc,
            "merchant_name": _MERCHANT_NAMES.get(mcc, "Retail Store"),
            "location": location,
            "device_id": f"DEV-{transaction_index % 30000:06d}",
            "ip_address": (
                f"192.168.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
            ),
            "fraud_label": 0,
            "fraud_typology": "",
            "fraud_ring_id": "",
            "velocity_flag": 0,
            "amount_flag": int(amount > 5000.0),
            "geo_flag": 0,
        }

    def generate_temporal_patterns(
        self,
        num_sequences: int,
        sequence_length: int,
        fraud_typologies: list[str],
        seed: int | None = None,
    ) -> dict[str, Any]:
        """Generate temporal fraud pattern sequences for sequence model training.

        Produces time-ordered transaction sequences with encoded temporal
        features for RNN/LSTM/Transformer fraud detection model training.

        Args:
            num_sequences: Number of account sequences to generate.
            sequence_length: Number of transactions per sequence.
            fraud_typologies: Fraud typologies to include in sequences.
            seed: Random seed.

        Returns:
            Temporal pattern dataset dict with sequences and labels.
        """
        rng = random.Random(seed)
        sequences: list[dict[str, Any]] = []

        for seq_idx in range(num_sequences):
            is_fraud_sequence = rng.random() < 0.15
            account_id = f"ACC-{seq_idx:08d}"
            transactions: list[dict[str, Any]] = []

            for step in range(sequence_length):
                hours_offset = step * rng.uniform(1, 48)
                timestamp = datetime.now(timezone.utc) - timedelta(
                    hours=(sequence_length - step) * 24
                ) + timedelta(hours=hours_offset)

                if is_fraud_sequence and step >= sequence_length - 3:
                    typology = rng.choice(fraud_typologies)
                    tp = _FRAUD_TYPOLOGIES.get(typology, _FRAUD_TYPOLOGIES["card_not_present"])
                    amt_min, amt_max = tp["typical_amount_range"]
                    amount = round(rng.uniform(amt_min, amt_max), 2)
                    fraud_flag = 1
                else:
                    import math
                    amount = round(max(1.0, math.exp(rng.gauss(4.0, 1.0))), 2)
                    fraud_flag = 0

                transactions.append({
                    "step": step,
                    "timestamp": timestamp.isoformat(),
                    "amount": amount,
                    "hour_of_day": timestamp.hour,
                    "day_of_week": timestamp.weekday(),
                    "fraud_label": fraud_flag,
                })

            sequences.append({
                "account_id": account_id,
                "sequence_fraud_label": int(is_fraud_sequence),
                "sequence_length": sequence_length,
                "transactions": transactions,
            })

        fraud_sequences = sum(1 for s in sequences if s["sequence_fraud_label"])

        result = {
            "num_sequences": num_sequences,
            "sequence_length": sequence_length,
            "fraud_sequences": fraud_sequences,
            "legitimate_sequences": num_sequences - fraud_sequences,
            "fraud_sequence_rate": round(fraud_sequences / num_sequences, 4) if num_sequences > 0 else 0.0,
            "sequences": sequences,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "Temporal fraud patterns generated",
            num_sequences=num_sequences,
            fraud_sequences=fraud_sequences,
        )

        return result


__all__ = ["FraudPatternGenerator"]
