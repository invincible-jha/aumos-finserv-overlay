# Changelog

All notable changes to aumos-finserv-overlay are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-02-26

### Added
- SOX compliance evidence collection with COSO control area classification
- SOX compliance status aggregation with attestation readiness indicator
- SR 11-7 model risk assessments with automatic risk tiering (low/medium/high/critical)
- SR 11-7 risk score computation: exposure (40%), regulatory capital (25%), customer-facing (20%), limitations (15%)
- PCI DSS v4.0 control scanning across all 12 requirement areas
- DORA ICT operational resilience status with RTO/RPO threshold monitoring
- Synthetic financial transaction generation with configurable fraud injection rates
- Regulatory report generation for SEC (Form 10-K/10-Q), FINRA FOCUS, CFPB, OCC Call Report, DORA Incident
- SEC AI governance disclosure sections aligned with 2024 SEC AI guidance
- XBRL output for SEC filings, PDF for regulatory submissions, JSON for FDIC
- Database models: fsv_sox_evidence, fsv_model_risk_assessments, fsv_pci_controls, fsv_dora_assessments, fsv_synthetic_transactions, fsv_regulatory_reports
- Kafka events for all compliance domain actions
- FastAPI service on port 8000 with full hexagonal architecture
