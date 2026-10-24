# Secure Lens — Complete AI-Powered Web Security Platform

Secure Lens is an enterprise-grade web application security assessment platform built for website owners, authorized developers, and security engineers to discover, understand, prioritize, and remediate web vulnerabilities with AI-grounded engineering guidance.

---

## 1. Architecture Overview

Secure Lens coordinates multiple defensive scanning engines, normalizes security alerts, eliminates duplicate reports, and integrates server-side AI (via `@google/genai`) to generate remediation code (Nginx, Apache, Express, Caddy) and CLI verification curl commands.

```
                      +---------------------------------------+
                      |       Secure Lens Frontend (React)    |
                      |   Dashboard • Scans • AI Copilot      |
                      +-------------------+-------------------+
                                          |
                                    REST API (JSON)
                                          |
                      +-------------------+-------------------+
                      |       Secure Lens Express Backend     |
                      |  SSRF Guard • Orchestrator • Auth     |
                      +--+--------+--------+---------+--------+
                         |        |        |         |
    +--------------------+  +-----+---+  +-+-----+  ++----------------+
    | HTTP Security Headers | testssl |  | WhatWeb  |  OWASP ZAP /    |
    | & Cookie Inspector   | TLS/SSL |  | Finger-  |  Nuclei Safe    |
    |                      | Certs   |  | printing |  Templates      |
    +----------------------+---------+  +---------+  +----------------+
                                          |
                               +----------+----------+
                               |  Google AI Engine   |
                               |  (gemini-3.8-flash) |
                               +---------------------+
```

### Integrated Security Engines:
1. **HTTP Security Headers & Policy Inspector**: Evaluates HSTS (`Strict-Transport-Security`), Content Security Policy (`CSP`), `X-Frame-Options` (Clickjacking), `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, Cookie flags (`Secure`, `HttpOnly`, `SameSite`), and server banner disclosures.
2. **TLS / SSL Certificate Inspector (testssl adapter)**: Native TLS handshake engine inspecting X.509 certificate chains, expiration date windows, Subject Alternative Names (SAN), negotiated protocol versions (TLS 1.2, TLS 1.3), untrusted CAs, and weak cipher suites.
3. **WhatWeb Technology Fingerprinter**: Analyzes response headers, DOM markers, script tags, CMS identifiers (WordPress, Drupal, Shopify), and front-end frameworks (React, Vue, Next.js).
4. **OWASP ZAP Passive Rules Adapter**: Non-destructive passive checks for unauthenticated state-changing POST forms lacking anti-CSRF tokens, passive mixed content on HTTPS endpoints, exposed Git repositories (`/.git/HEAD`), sensitive environment secrets (`/.env`), and `robots.txt` disclosures.
5. **Nuclei Non-Intrusive Engine**: Curated non-destructive configuration templates detecting CORS arbitrary origin reflection with credentials, open directory indexing (`Index of /`), and exposed Swagger / OpenAPI specifications.
6. **Nmap Safe Network Port Scanner (Opt-In Profile)**: Conservative TCP connect probes against standard web ports (80, 443, 8080, 8443) with strict 1200ms socket timeouts and no exploit scripts.

---

## 2. Security Boundaries & SSRF Defense

Secure Lens strictly blocks Server-Side Request Forgery (SSRF) and DNS rebinding attacks:
- **Private Subnets Blocked**: All loopback (`127.0.0.0/8`, `::1`), Class A/B/C private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), Carrier-Grade NAT (`100.64.0.0/10`), Link-Local (`169.254.0.0/16`), and Cloud Metadata endpoints (`169.254.169.254`, `metadata.google.internal`).
- **Dangerous Ports Filtered**: Restricted service ports (SSH 22, Telnet 23, SMTP 25, MySQL 3306, Postgres 5432, Redis 6379, MongoDB 27017) are blocked.
- **DNS Re-Validation**: Destination IP addresses are resolved and verified both at scan creation and immediately prior to socket connections to eliminate DNS-rebinding windows.
- **Mandatory Authorization Consent**: Scans cannot be executed without checking the explicit ownership and authorization declaration.

---

## 3. Mandatory AI Key & Configuration

Secure Lens connects to Google Gemini / Gemma via the `@google/genai` TypeScript SDK on the server:
- Model: `gemini-3.8-flash` (or custom `AI_MODEL`).
- Environment variable: `GEMINI_API_KEY` (configured in server `.env` or system environment).
- Secret Safety: The API key is **never** sent to the client, exposed in browser storage, or echoed in logs.

### Testing AI Connection:
In **Settings > AI Security Engine Status**, click **Test AI Connection** to verify roundtrip latency and connectivity without exposing secrets.

---

## 4. Running the Platform Locally

### Prerequisites:
- Node.js 18.0.0+ or Node 20.x+
- npm or pnpm

### Setup:
```bash
# 1. Clone the repository
git clone <repository_url>
cd secure-lens

# 2. Install dependencies
npm install

# 3. Create .env file with your Gemini API Key
cp .env.example .env
# Edit .env and set:
# GEMINI_API_KEY=your_gemini_api_key

# 4. Start the full-stack platform (Express + Vite on Port 3000)
npm run dev
```

Visit `http://localhost:3000` in your web browser.

### Default Pre-Seeded Accounts:
- **Security Analyst Profile**: `analyst@securelens.local`
- **Password**: `SecurityLens2026!`
*(You can also register a new account anytime via the Sign In modal).*

---

## 5. Running Automated Tests

Secure Lens includes an automated test runner validating SSRF blocking, DNS verification, cryptographic password hashing, token expiration, finding deduplication, and report generation:

```bash
npm test
```

---

## 6. Report Generation

Audit findings can be exported in two formats directly from any completed scan:
- **Printable Executive HTML Report**: Formal security assessment document with executive summary, posture score, methodology, findings table, code fixes, and limitation disclaimer.
- **Machine-Readable JSON**: Full structured telemetry export for integration into SIEM, CI/CD pipelines, or ticketing systems.

---

## 7. Authorized Use Policy & Limitations

1. **Defensive Assessment Only**: Secure Lens is designed exclusively for defense-in-depth vulnerability discovery and security posture auditing.
2. **Explicit Authorization**: Only scan domains and web applications that you own or have explicit written permission to test.
3. **Assessment Limitations**: Automated scanning does not substitute for deep manual penetration testing, business logic reviews, or complete source code reviews.
4. **Separation of Evidence**: All scanner findings are strictly segregated from AI-generated interpretations. Observable raw evidence is preserved verbatim.

---

## 8. License

Apache 2.0 License.
