# aumos-finserv-overlay

Financial services vertical overlay for the AumOS Enterprise platform.

Provides SOX compliance evidence management, SR 11-7 model risk assessments, PCI DSS v4.0
control scanning, DORA ICT resilience status, synthetic financial transaction generation,
and regulatory reporting (SEC, CFPB, FINRA, OCC, FDIC, FRB).

## Purpose

Financial institutions using AumOS need regulator-specific compliance guardrails beyond
the core governance engine. This overlay provides:

- **SOX (Sarbanes-Oxley)**: Evidence collection, COSO control classification, 7-year
  immutable retention, and management attestation readiness tracking.
- **SEC AI Guidance**: AI governance disclosures aligned with SEC 2024 AI guidance,
  integrated with the SR 11-7 model inventory.
- **SR 11-7 Model Risk**: Federal Reserve / OCC model risk assessment with automatic
  risk tiering (low/medium/high/critical), exposure scoring, and independent validation
  tracking.
- **PCI DSS v4.0**: Cardholder data environment control scanning across all 12
  requirements, producing QSA-ready evidence packages.
- **DORA**: EU Digital Operational Resilience Act ICT resilience status, RTO/RPO
  compliance monitoring, and incident reporting readiness.
- **Synthetic Transactions**: Realistic financial transaction datasets with configurable
  fraud injection rates for ML model training and fraud detection pipeline testing.
- **Regulatory Reports**: PDF, XBRL, and JSON report generation for SEC Form 10-K/10-Q,
  FINRA FOCUS, CFPB, Call Reports, and DORA Incident reports.

## Architecture

```
src/aumos_finserv_overlay/
├── __init__.py
├── main.py                   # FastAPI app entry point
├── settings.py               # Pydantic settings (AUMOS_FINSERV_ prefix)
├── api/
│   ├── router.py             # All HTTP routes
│   └── schemas.py            # Request/response Pydantic models
├── core/
│   ├── models.py             # SQLAlchemy ORM models (fsv_ prefix)
│   ├── services.py           # Business logic (6 services)
│   └── interfaces.py         # Protocol interfaces for DI
└── adapters/
    ├── repositories.py       # SQLAlchemy async repositories
    ├── transaction_generator.py  # Synthetic transaction CSV generator
    ├── report_generator.py   # Regulatory report document generator
    └── kafka.py              # Kafka event publisher
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/finserv/sox/evidence` | Collect SOX compliance evidence |
| GET  | `/api/v1/finserv/sox/status` | SOX compliance status summary |
| POST | `/api/v1/finserv/model-risk/assess` | SR 11-7 model risk assessment |
| GET  | `/api/v1/finserv/model-risk/{id}` | Model risk assessment detail |
| POST | `/api/v1/finserv/pci-dss/scan` | PCI DSS v4.0 control scan |
| GET  | `/api/v1/finserv/dora/status` | DORA ICT resilience status |
| POST | `/api/v1/finserv/synth/transactions` | Generate synthetic transactions |
| GET  | `/api/v1/finserv/reports` | List regulatory reports |
| POST | `/api/v1/finserv/reports/generate` | Generate regulatory report |

## Database Tables

| Table | Description |
|-------|-------------|
| `fsv_sox_evidence` | SOX internal control evidence records |
| `fsv_model_risk_assessments` | SR 11-7 model risk assessments |
| `fsv_pci_controls` | PCI DSS v4.0 control scan results |
| `fsv_dora_assessments` | DORA ICT resilience assessments |
| `fsv_synthetic_transactions` | Synthetic transaction generation jobs |
| `fsv_regulatory_reports` | Generated regulatory report metadata |

## Quick Start

```bash
cp .env.example .env
# Edit .env with your database and Kafka settings

make install
make docker-run   # Start Postgres + Kafka
make migrate      # Run database migrations
uvicorn aumos_finserv_overlay.main:app --reload
```

## Configuration

All settings use the `AUMOS_FINSERV_` prefix. See `.env.example` for the full list.

Key settings:
- `AUMOS_FINSERV_SOX_CONTROL_FRAMEWORK` — COSO (default) or COBIT
- `AUMOS_FINSERV_SR117_HIGH_RISK_THRESHOLD` — Risk score threshold for high-risk tier (default 0.7)
- `AUMOS_FINSERV_PCI_DSS_VERSION` — PCI DSS version (default 4.0)
- `AUMOS_FINSERV_DORA_RTO_THRESHOLD_HOURS` — Max acceptable RTO (default 4 hours)
- `AUMOS_FINSERV_SYNTH_MAX_TRANSACTIONS_PER_REQUEST` — Generation limit (default 1M)

## License

Apache-2.0 — see [LICENSE](LICENSE).
