# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

Report security vulnerabilities to security@muveraai.com.

Do NOT open a public GitHub issue for security vulnerabilities.

## Security Controls

- All API endpoints require JWT authentication via `aumos_common.auth`
- Tenant isolation enforced at every database query (tenant_id guard)
- PII masking enabled by default in synthetic transaction output
- SOX evidence records are immutable once created (no DELETE endpoints)
- PCI DSS cardholder data is never stored — only control scan metadata
- All secrets via environment variables — never hardcoded
- Database connections use parameterised queries (SQLAlchemy ORM)
- Non-root Docker user (`aumos:aumos`)

## Data Classification

- SOX evidence: Confidential — 7-year retention required
- Model risk assessments: Confidential — SEC disclosure may apply
- PCI DSS scan results: Restricted — QSA access controls required
- Synthetic transactions: Internal — no real PII
- Regulatory reports: Confidential — regulator submission required
