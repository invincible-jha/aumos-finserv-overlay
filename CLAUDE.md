# aumos-finserv-overlay — Agent Instructions

## Purpose
Financial services vertical overlay. Provides SOX evidence management, SR 11-7 model risk,
PCI DSS v4.0 scanning, DORA resilience status, synthetic transaction generation, and
regulatory reporting.

## Package
- Package: `aumos_finserv_overlay`
- Table prefix: `fsv_`
- Env prefix: `AUMOS_FINSERV_`
- Port: 8000

## Architecture
Hexagonal — api/ (routes + schemas) → core/ (services + models + interfaces) → adapters/ (repos + generators).
Services are injected via FastAPI Depends; all dependencies are constructor-injected.

## Key Compliance Domains
- **SOX**: COSO/COBIT, 7-year evidence retention (2555 days), PCAOB alignment
- **SR 11-7**: Federal Reserve / OCC model risk, 5-factor risk scoring, automatic tier assignment
- **PCI DSS v4.0**: 12 requirement areas, QSA-ready evidence packages
- **DORA**: EU 2022/2554, RTO/RPO thresholds (4h/1h default), ICT third-party register
- **SEC AI Guidance**: 2024-01 version, materiality threshold 5%, AI disclosure in reports
- **Regulators**: SEC, CFPB, FINRA, OCC, FDIC, FRB

## Development Notes
- All services import from `aumos_common` for auth, db, events, errors, observability
- Risk score computation: exposure (40%) + regulatory_capital_impact (25%) + customer_facing (20%) + limitations (15%)
- Transaction generator: CSV output, log-normal amount distribution, Faker-free (uses deterministic indices)
- Report generator: JSON → XBRL (SEC) / PDF (FINRA/FRB/CFPB/OCC) / JSON (FDIC)
